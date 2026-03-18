.class public interface abstract Lq61/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc81/e;
.implements Lt61/p;


# virtual methods
.method public dispatchTouchEvent(Landroid/view/MotionEvent;)V
    .locals 8

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lq61/j;->getDeviceDisplayWidthInPx()Ljava/lang/Float;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-eqz v0, :cond_3

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    invoke-interface {p0}, Lq61/j;->getDeviceDisplayHeightInPx()Ljava/lang/Float;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eqz v0, :cond_2

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getRawX()F

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getRawY()F

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    int-to-short v6, v0

    .line 39
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getAction()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    const/4 v1, 0x1

    .line 44
    if-eq v0, v1, :cond_1

    .line 45
    .line 46
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getAction()I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    const/4 v0, 0x3

    .line 51
    if-ne p1, v0, :cond_0

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const/4 v1, 0x0

    .line 55
    :cond_1
    :goto_0
    move v7, v1

    .line 56
    invoke-interface {p0}, Lq61/j;->getRpaViewModel()Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-interface/range {v1 .. v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;->onTouchPositionChanged(FFFFSZ)V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_2
    new-instance p1, Lpd/f0;

    .line 65
    .line 66
    const/16 v0, 0x11

    .line 67
    .line 68
    invoke-direct {p1, v0}, Lpd/f0;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-static {p0, p1}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 72
    .line 73
    .line 74
    return-void

    .line 75
    :cond_3
    new-instance p1, Lpd/f0;

    .line 76
    .line 77
    const/16 v0, 0x10

    .line 78
    .line 79
    invoke-direct {p1, v0}, Lpd/f0;-><init>(I)V

    .line 80
    .line 81
    .line 82
    invoke-static {p0, p1}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 83
    .line 84
    .line 85
    return-void
.end method

.method public abstract getDeviceDisplayHeightInPx()Ljava/lang/Float;
.end method

.method public abstract getDeviceDisplayWidthInPx()Ljava/lang/Float;
.end method

.method public abstract getRpaScreenViewModel()Lyy0/j1;
.end method

.method public abstract getRpaViewModel()Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;
.end method

.method public abstract getWindowCallback()Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;
.end method

.method public abstract getWindowHasFocus()Lyy0/j1;
.end method

.method public navigateTo(Le81/t;)V
    .locals 5

    .line 1
    const-string v0, "viewModelController"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lmc/e;

    .line 7
    .line 8
    const/16 v1, 0x1b

    .line 9
    .line 10
    invoke-direct {v0, p1, v1}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {p0, v0}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p0}, Lq61/j;->getRpaScreenViewModel()Lyy0/j1;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Lyy0/c2;

    .line 21
    .line 22
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Lx61/a;

    .line 27
    .line 28
    instance-of v1, v0, Lv61/a;

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    if-eqz v1, :cond_0

    .line 32
    .line 33
    move-object v1, v0

    .line 34
    check-cast v1, Lv61/a;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move-object v1, v2

    .line 38
    :goto_0
    if-eqz v1, :cond_1

    .line 39
    .line 40
    invoke-interface {v1}, Lv61/a;->getViewModelControllerHashCode()I

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-ne v3, v4, :cond_1

    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    if-eqz v1, :cond_2

    .line 52
    .line 53
    invoke-interface {v1}, Ljava/io/Closeable;->close()V

    .line 54
    .line 55
    .line 56
    :cond_2
    invoke-interface {p0}, Lq61/j;->getRpaScreenViewModel()Lyy0/j1;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    instance-of v1, p1, Le81/l;

    .line 61
    .line 62
    const/4 v3, 0x2

    .line 63
    const/4 v4, 0x0

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;

    .line 67
    .line 68
    check-cast p1, Le81/l;

    .line 69
    .line 70
    invoke-direct {v0, p1, v4, v3, v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;-><init>(Le81/l;IILkotlin/jvm/internal/g;)V

    .line 71
    .line 72
    .line 73
    goto/16 :goto_1

    .line 74
    .line 75
    :cond_3
    instance-of v1, p1, Le81/s;

    .line 76
    .line 77
    if-eqz v1, :cond_4

    .line 78
    .line 79
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;

    .line 80
    .line 81
    check-cast p1, Le81/s;

    .line 82
    .line 83
    invoke-direct {v0, p1, v4, v3, v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/TouchDiagnosisViewModelImpl;-><init>(Le81/s;IILkotlin/jvm/internal/g;)V

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_4
    instance-of v1, p1, Le81/n;

    .line 88
    .line 89
    if-eqz v1, :cond_5

    .line 90
    .line 91
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;

    .line 92
    .line 93
    check-cast p1, Le81/n;

    .line 94
    .line 95
    invoke-direct {v0, p1, v4, v3, v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveActivationViewModelImpl;-><init>(Le81/n;IILkotlin/jvm/internal/g;)V

    .line 96
    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_5
    instance-of v1, p1, Le81/r;

    .line 100
    .line 101
    if-eqz v1, :cond_7

    .line 102
    .line 103
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;

    .line 104
    .line 105
    if-eqz v1, :cond_6

    .line 106
    .line 107
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;

    .line 108
    .line 109
    check-cast p1, Le81/r;

    .line 110
    .line 111
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->update$remoteparkassistplugin_release(Le81/r;)V

    .line 112
    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_6
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;

    .line 116
    .line 117
    check-cast p1, Le81/r;

    .line 118
    .line 119
    invoke-direct {v0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;-><init>(Le81/r;)V

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_7
    instance-of v1, p1, Le81/m;

    .line 124
    .line 125
    if-eqz v1, :cond_9

    .line 126
    .line 127
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;

    .line 128
    .line 129
    if-eqz v1, :cond_8

    .line 130
    .line 131
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;

    .line 132
    .line 133
    check-cast p1, Le81/m;

    .line 134
    .line 135
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->update$remoteparkassistplugin_release(Le81/m;)V

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_8
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;

    .line 140
    .line 141
    check-cast p1, Le81/m;

    .line 142
    .line 143
    invoke-direct {v0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;-><init>(Le81/m;)V

    .line 144
    .line 145
    .line 146
    goto :goto_1

    .line 147
    :cond_9
    instance-of v0, p1, Le81/o;

    .line 148
    .line 149
    if-eqz v0, :cond_a

    .line 150
    .line 151
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveCorrectionViewModelImpl;

    .line 152
    .line 153
    check-cast p1, Le81/o;

    .line 154
    .line 155
    invoke-direct {v0, p1, v4, v3, v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/DriveCorrectionViewModelImpl;-><init>(Le81/o;IILkotlin/jvm/internal/g;)V

    .line 156
    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_a
    instance-of v0, p1, Le81/q;

    .line 160
    .line 161
    if-eqz v0, :cond_b

    .line 162
    .line 163
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;

    .line 164
    .line 165
    check-cast p1, Le81/q;

    .line 166
    .line 167
    invoke-direct {v0, p1, v4, v3, v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFinishedViewModelImpl;-><init>(Le81/q;IILkotlin/jvm/internal/g;)V

    .line 168
    .line 169
    .line 170
    goto :goto_1

    .line 171
    :cond_b
    instance-of v0, p1, Le81/p;

    .line 172
    .line 173
    if-eqz v0, :cond_c

    .line 174
    .line 175
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFailedViewModelImpl;

    .line 176
    .line 177
    check-cast p1, Le81/p;

    .line 178
    .line 179
    invoke-direct {v0, p1, v4, v3, v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ParkingFailedViewModelImpl;-><init>(Le81/p;IILkotlin/jvm/internal/g;)V

    .line 180
    .line 181
    .line 182
    :goto_1
    check-cast p0, Lyy0/c2;

    .line 183
    .line 184
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 185
    .line 186
    .line 187
    invoke-virtual {p0, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    return-void

    .line 191
    :cond_c
    new-instance p0, La8/r0;

    .line 192
    .line 193
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 194
    .line 195
    .line 196
    throw p0
.end method

.method public setUpWindowCallbacks(Landroid/view/Window;)V
    .locals 3

    .line 1
    const-string v0, "window"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;

    .line 7
    .line 8
    invoke-virtual {p1}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const-string v2, "getCallback(...)"

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;-><init>(Landroid/view/Window$Callback;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->setWindowEventDelegate$remoteparkassistplugin_release(Lt61/p;)V

    .line 21
    .line 22
    .line 23
    invoke-interface {p0, v0}, Lq61/j;->setWindowCallback(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, v0}, Landroid/view/Window;->setCallback(Landroid/view/Window$Callback;)V

    .line 27
    .line 28
    .line 29
    new-instance v1, Lq61/i;

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    invoke-direct {v1, p1, p0, v2}, Lq61/i;-><init>(Landroid/view/Window;Lq61/j;I)V

    .line 33
    .line 34
    .line 35
    invoke-static {v0, v1}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public abstract setWindowCallback(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;)V
.end method

.method public tearDownWindowCallbacks(Landroid/view/Window;)V
    .locals 2

    .line 1
    const-string v0, "window"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lq61/i;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    invoke-direct {v0, p1, p0, v1}, Lq61/i;-><init>(Landroid/view/Window;Lq61/j;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 13
    .line 14
    .line 15
    invoke-interface {p0}, Lq61/j;->getWindowCallback()Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->getConcreteWindowCallback()Landroid/view/Window$Callback;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    invoke-virtual {p1, v0}, Landroid/view/Window;->setCallback(Landroid/view/Window$Callback;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    const/4 p1, 0x0

    .line 31
    invoke-interface {p0, p1}, Lq61/j;->setWindowCallback(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public updateRPALifecycle(ZLandroidx/lifecycle/q;)V
    .locals 3

    .line 1
    const-string v0, "appLifecycle"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_4

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    if-eq v0, v1, :cond_3

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    if-eq v0, v1, :cond_3

    .line 17
    .line 18
    const/4 v1, 0x3

    .line 19
    if-eq v0, v1, :cond_1

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    if-ne v0, v1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    if-eqz p1, :cond_2

    .line 32
    .line 33
    sget-object v0, Ln71/c;->e:Ln71/c;

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_2
    sget-object v0, Ln71/c;->f:Ln71/c;

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_3
    sget-object v0, Ln71/c;->g:Ln71/c;

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_4
    sget-object v0, Ln71/c;->h:Ln71/c;

    .line 43
    .line 44
    :goto_1
    new-instance v1, Lb71/o;

    .line 45
    .line 46
    const/4 v2, 0x3

    .line 47
    invoke-direct {v1, p1, p2, v0, v2}, Lb71/o;-><init>(ZLjava/lang/Object;Ljava/lang/Object;I)V

    .line 48
    .line 49
    .line 50
    invoke-static {p0, v1}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 51
    .line 52
    .line 53
    invoke-interface {p0}, Lq61/j;->getRpaViewModel()Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-interface {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;->onLifecycleChanged(Ln71/c;)V

    .line 58
    .line 59
    .line 60
    return-void
.end method
