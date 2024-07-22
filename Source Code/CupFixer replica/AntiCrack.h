#ifndef ANTI_CRACK_H
#define ANTI_CRACK_H

#include <string>

namespace AntiCrack
{
    int getProcID(const std::string& p_name);
    bool isProcRunning(const std::string& process);

    namespace BSOD
    {
        void bsod();
    }

    void Tick();
}

#endif // ANTI_CRACK_H