#include <windows.h>
#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

static std::vector<unsigned char> resourceBytes(int id) {
  HRSRC r=FindResourceW(nullptr,MAKEINTRESOURCEW(id),MAKEINTRESOURCEW(10)); if(!r) throw 1;
  HGLOBAL h=LoadResource(nullptr,r); if(!h) throw 1;
  DWORD n=SizeofResource(nullptr,r); void* p=LockResource(h); if(!p||!n) throw 1;
  return std::vector<unsigned char>((unsigned char*)p,(unsigned char*)p+n);
}
static std::string sha256(const std::vector<unsigned char>& d) {
  BCRYPT_ALG_HANDLE a=nullptr; BCRYPT_HASH_HANDLE h=nullptr; DWORD obj=0,cb=0;
  if(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0) throw 2;
  if(BCryptGetProperty(a,BCRYPT_OBJECT_LENGTH,(PUCHAR)&obj,sizeof(obj),&cb,0)<0) throw 2;
  std::vector<unsigned char> o(obj), out(32);
  if(BCryptCreateHash(a,&h,o.data(),obj,nullptr,0,0)<0) throw 2;
  if(BCryptHashData(h,(PUCHAR)d.data(),(ULONG)d.size(),0)<0||BCryptFinishHash(h,out.data(),32,0)<0) throw 2;
  BCryptDestroyHash(h); BCryptCloseAlgorithmProvider(a,0);
  const char* x="0123456789abcdef"; std::string s; s.reserve(64);
  for(auto v:out){s+=x[v>>4];s+=x[v&15];} return s;
}
static void writeFile(const std::filesystem::path& p,const std::vector<unsigned char>& d){
  std::ofstream f(p,std::ios::binary|std::ios::trunc); if(!f) throw 3;
  f.write((const char*)d.data(),(std::streamsize)d.size()); if(!f) throw 3;
}
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
  std::filesystem::path dir;
  try {
    auto payload=resourceBytes(101), script=resourceBytes(102);
    if(sha256(payload)!=PAYLOAD_SHA256 || sha256(script)!=INSTALL_SCRIPT_SHA256) { MessageBoxW(nullptr,L"Embedded installer integrity check failed.",L"MalGuard Setup",MB_ICONERROR); return 10; }
    wchar_t tmp[MAX_PATH]; if(!GetTempPathW(MAX_PATH,tmp)) throw 4;
    dir=std::filesystem::path(tmp)/(L"MalGuardSetup-"+std::to_wstring(GetCurrentProcessId()));
    std::filesystem::create_directories(dir);
    auto zip=dir/L"payload.zip", ps=dir/L"install.ps1"; writeFile(zip,payload); writeFile(ps,script);
    std::wstring cmd=L"powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+ps.wstring()+L"\"";
    STARTUPINFOW si{sizeof(si)}; PROCESS_INFORMATION pi{}; std::vector<wchar_t> buf(cmd.begin(),cmd.end()); buf.push_back(0);
    if(!CreateProcessW(nullptr,buf.data(),nullptr,nullptr,FALSE,0,nullptr,dir.c_str(),&si,&pi)) throw 5;
    WaitForSingleObject(pi.hProcess,INFINITE); DWORD ec=1; GetExitCodeProcess(pi.hProcess,&ec); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    std::filesystem::remove_all(dir); return (int)ec;
  } catch (...) { if(!dir.empty()) { std::error_code e; std::filesystem::remove_all(dir,e); } MessageBoxW(nullptr,L"MalGuard Setup could not start safely.",L"MalGuard Setup",MB_ICONERROR); return 20; }
}
