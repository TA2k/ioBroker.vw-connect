.class public final Lw0/m;
.super Landroid/view/View;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Landroid/view/Window;

.field public e:Lw0/l;


# direct methods
.method public static synthetic a(Lw0/m;F)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lw0/m;->setBrightness(F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private getBrightness()F
    .locals 1

    .line 1
    iget-object p0, p0, Lw0/m;->d:Landroid/view/Window;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const-string p0, "ScreenFlashView"

    .line 6
    .line 7
    const-string v0, "setBrightness: mScreenFlashWindow is null!"

    .line 8
    .line 9
    invoke-static {p0, v0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const/high16 p0, 0x7fc00000    # Float.NaN

    .line 13
    .line 14
    return p0

    .line 15
    :cond_0
    invoke-virtual {p0}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    iget p0, p0, Landroid/view/WindowManager$LayoutParams;->screenBrightness:F

    .line 20
    .line 21
    return p0
.end method

.method private setBrightness(F)V
    .locals 2

    .line 1
    iget-object v0, p0, Lw0/m;->d:Landroid/view/Window;

    .line 2
    .line 3
    const-string v1, "ScreenFlashView"

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string p0, "setBrightness: mScreenFlashWindow is null!"

    .line 8
    .line 9
    invoke-static {v1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-static {p1}, Ljava/lang/Float;->isNaN(F)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    const-string p0, "setBrightness: value is NaN!"

    .line 20
    .line 21
    invoke-static {v1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_1
    iget-object v0, p0, Lw0/m;->d:Landroid/view/Window;

    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    iput p1, v0, Landroid/view/WindowManager$LayoutParams;->screenBrightness:F

    .line 32
    .line 33
    iget-object p0, p0, Lw0/m;->d:Landroid/view/Window;

    .line 34
    .line 35
    invoke-virtual {p0, v0}, Landroid/view/Window;->setAttributes(Landroid/view/WindowManager$LayoutParams;)V

    .line 36
    .line 37
    .line 38
    new-instance p0, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string p1, "Brightness set to "

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    iget p1, v0, Landroid/view/WindowManager$LayoutParams;->screenBrightness:F

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-static {v1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    return-void
.end method

.method private setScreenFlashUiInfo(Lb0/s0;)V
    .locals 0

    .line 1
    const-string p0, "ScreenFlashView"

    .line 2
    .line 3
    const-string p1, "setScreenFlashUiInfo: mCameraController is null!"

    .line 4
    .line 5
    invoke-static {p0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public getScreenFlash()Lb0/s0;
    .locals 0

    .line 1
    iget-object p0, p0, Lw0/m;->e:Lw0/l;

    .line 2
    .line 3
    return-object p0
.end method

.method public getVisibilityRampUpAnimationDurationMillis()J
    .locals 2

    .line 1
    const-wide/16 v0, 0x3e8

    .line 2
    .line 3
    return-wide v0
.end method

.method public setController(Lw0/a;)V
    .locals 0

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public setScreenFlashWindow(Landroid/view/Window;)V
    .locals 4

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 5
    .line 6
    const-string v1, "updateScreenFlash: is new window null = "

    .line 7
    .line 8
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x1

    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    move v3, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v3, v1

    .line 18
    :goto_0
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v3, ",  is new window same as previous = "

    .line 22
    .line 23
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    iget-object v3, p0, Lw0/m;->d:Landroid/view/Window;

    .line 27
    .line 28
    if-ne p1, v3, :cond_1

    .line 29
    .line 30
    move v1, v2

    .line 31
    :cond_1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    const-string v1, "ScreenFlashView"

    .line 39
    .line 40
    invoke-static {v1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iget-object v0, p0, Lw0/m;->d:Landroid/view/Window;

    .line 44
    .line 45
    if-eq v0, p1, :cond_3

    .line 46
    .line 47
    if-nez p1, :cond_2

    .line 48
    .line 49
    const/4 v0, 0x0

    .line 50
    goto :goto_1

    .line 51
    :cond_2
    new-instance v0, Lw0/l;

    .line 52
    .line 53
    invoke-direct {v0, p0}, Lw0/l;-><init>(Lw0/m;)V

    .line 54
    .line 55
    .line 56
    :goto_1
    iput-object v0, p0, Lw0/m;->e:Lw0/l;

    .line 57
    .line 58
    :cond_3
    iput-object p1, p0, Lw0/m;->d:Landroid/view/Window;

    .line 59
    .line 60
    invoke-virtual {p0}, Lw0/m;->getScreenFlash()Lb0/s0;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-direct {p0, p1}, Lw0/m;->setScreenFlashUiInfo(Lb0/s0;)V

    .line 65
    .line 66
    .line 67
    return-void
.end method
