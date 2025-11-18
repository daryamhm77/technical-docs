# GPS Data Flow

```mermaid
flowchart TD
    %% ====================================================
    %% NODES
    %% ====================================================

    %% INPUT
    gpsInput([GPS Data])

    %% STAGE 1
    firstProcess[First process of device data stage]
    validateLength{Is GPS data < 300 and has time field?}
    validationError([Throw error])
    signal[Signal]
    S3[(S3 Storage)]

    %% STAGE 2
    extractData[Get signal, acceleration, laser and laserV data]
    missingData{Missing acceleration OR laser OR laserV?}
    returnSignal([Return signal])

    %% ACCELERATION
    accelExists{Acceleration exists?}
    extractAccel[Extract acceleration and send with formatted GPS]

    %% LASER
    laserExists{Laser exists?}
    sendLaser[Send Laser data to Computational Server]

    %% LASER V
    laserVExists{LaserV exists?}
    sendLaserV[Send LaserV data to Computational Server]

    %% END
    END([End])

    %% ====================================================
    %% MAIN FLOW
    %% ====================================================

    gpsInput --> firstProcess
    firstProcess --> validateLength

    validateLength -- Yes --> extractData
    validateLength -- No --> validationError --> END

    extractData --> missingData

    missingData -- Yes --> returnSignal --> END
    missingData -- No --> accelExists

    %% ACCELERATION PATH
    accelExists -- Yes --> extractAccel --> END
    accelExists -- No --> laserExists

    %% LASER PATH
    laserExists -- Yes --> sendLaser --> END
    laserExists -- No --> laserVExists

    %% LASER V PATH
    laserVExists -- Yes --> sendLaserV --> END
    laserVExists -- No --> END

    %% EXTRA INPUTS TO EXTRACT STEP
    signal --> extractData
    S3 --> extractData
