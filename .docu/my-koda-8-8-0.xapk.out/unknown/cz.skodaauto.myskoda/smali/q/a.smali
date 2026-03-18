.class public final Lq/a;
.super Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lq/d;


# direct methods
.method public constructor <init>(Lq/d;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lq/a;->a:Lq/d;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onAuthenticationError(ILjava/lang/CharSequence;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lq/a;->a:Lq/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lq/d;->a(ILjava/lang/CharSequence;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onAuthenticationFailed()V
    .locals 1

    .line 1
    iget-object p0, p0, Lq/a;->a:Lq/d;

    .line 2
    .line 3
    check-cast p0, Lq/p;

    .line 4
    .line 5
    iget-object p0, p0, Lq/p;->a:Ljava/lang/ref/WeakReference;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Lq/s;

    .line 18
    .line 19
    iget-boolean v0, v0, Lq/s;->l:Z

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lq/s;

    .line 28
    .line 29
    iget-object v0, p0, Lq/s;->s:Landroidx/lifecycle/i0;

    .line 30
    .line 31
    if-nez v0, :cond_0

    .line 32
    .line 33
    new-instance v0, Landroidx/lifecycle/i0;

    .line 34
    .line 35
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 36
    .line 37
    .line 38
    iput-object v0, p0, Lq/s;->s:Landroidx/lifecycle/i0;

    .line 39
    .line 40
    :cond_0
    iget-object p0, p0, Lq/s;->s:Landroidx/lifecycle/i0;

    .line 41
    .line 42
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 43
    .line 44
    invoke-static {p0, v0}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    return-void
.end method

.method public onAuthenticationHelp(ILjava/lang/CharSequence;)V
    .locals 0

    .line 1
    return-void
.end method

.method public onAuthenticationSucceeded(Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;)V
    .locals 4

    .line 1
    const/16 v0, 0x1e

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz p1, :cond_4

    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;->getCryptoObject()Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    if-nez v2, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-static {v2}, Lq/u;->d(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)Ljavax/crypto/Cipher;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    if-eqz v3, :cond_1

    .line 18
    .line 19
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 20
    .line 21
    invoke-direct {v1, v3}, Lcom/google/firebase/messaging/w;-><init>(Ljavax/crypto/Cipher;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-static {v2}, Lq/u;->f(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)Ljava/security/Signature;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    if-eqz v3, :cond_2

    .line 30
    .line 31
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 32
    .line 33
    invoke-direct {v1, v3}, Lcom/google/firebase/messaging/w;-><init>(Ljava/security/Signature;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_2
    invoke-static {v2}, Lq/u;->e(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)Ljavax/crypto/Mac;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    if-eqz v3, :cond_3

    .line 42
    .line 43
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 44
    .line 45
    invoke-direct {v1, v3}, Lcom/google/firebase/messaging/w;-><init>(Ljavax/crypto/Mac;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_3
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 50
    .line 51
    if-lt v3, v0, :cond_4

    .line 52
    .line 53
    invoke-static {v2}, Lq/v;->b(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)Landroid/security/identity/IdentityCredential;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    if-eqz v2, :cond_4

    .line 58
    .line 59
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 60
    .line 61
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/w;-><init>(Landroid/security/identity/IdentityCredential;)V

    .line 62
    .line 63
    .line 64
    :cond_4
    :goto_0
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 65
    .line 66
    const/4 v3, -0x1

    .line 67
    if-lt v2, v0, :cond_5

    .line 68
    .line 69
    if-eqz p1, :cond_7

    .line 70
    .line 71
    invoke-static {p1}, Lq/c;->a(Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;)I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    goto :goto_1

    .line 76
    :cond_5
    const/16 p1, 0x1d

    .line 77
    .line 78
    if-ne v2, p1, :cond_6

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_6
    const/4 v3, 0x2

    .line 82
    :cond_7
    :goto_1
    new-instance p1, Lq/n;

    .line 83
    .line 84
    invoke-direct {p1, v1, v3}, Lq/n;-><init>(Lcom/google/firebase/messaging/w;I)V

    .line 85
    .line 86
    .line 87
    iget-object p0, p0, Lq/a;->a:Lq/d;

    .line 88
    .line 89
    invoke-virtual {p0, p1}, Lq/d;->b(Lq/n;)V

    .line 90
    .line 91
    .line 92
    return-void
.end method
