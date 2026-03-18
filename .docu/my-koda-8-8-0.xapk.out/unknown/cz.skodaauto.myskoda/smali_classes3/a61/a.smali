.class public final La61/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lao/a;
.implements Lno/m;
.implements Lgs/e;
.implements Lf8/l;
.implements Lm6/c;
.implements Llp/jg;
.implements Lkx0/a;
.implements Lus/b;
.implements Lvp/u;
.implements Lx51/c;


# static fields
.field public static e:La61/a;

.field public static final synthetic f:La61/a;

.field public static final synthetic g:La61/a;

.field public static final synthetic h:La61/a;

.field public static final synthetic i:La61/a;

.field public static final synthetic j:La61/a;

.field public static final synthetic k:La61/a;

.field public static final synthetic l:La61/a;

.field public static final synthetic m:La61/a;

.field public static final synthetic n:La61/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, La61/a;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, La61/a;->f:La61/a;

    .line 9
    .line 10
    new-instance v0, La61/a;

    .line 11
    .line 12
    const/16 v1, 0x11

    .line 13
    .line 14
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, La61/a;->g:La61/a;

    .line 18
    .line 19
    new-instance v0, La61/a;

    .line 20
    .line 21
    const/16 v1, 0x12

    .line 22
    .line 23
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 24
    .line 25
    .line 26
    sput-object v0, La61/a;->h:La61/a;

    .line 27
    .line 28
    new-instance v0, La61/a;

    .line 29
    .line 30
    const/16 v1, 0x13

    .line 31
    .line 32
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 33
    .line 34
    .line 35
    sput-object v0, La61/a;->i:La61/a;

    .line 36
    .line 37
    new-instance v0, La61/a;

    .line 38
    .line 39
    const/16 v1, 0x14

    .line 40
    .line 41
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 42
    .line 43
    .line 44
    sput-object v0, La61/a;->j:La61/a;

    .line 45
    .line 46
    new-instance v0, La61/a;

    .line 47
    .line 48
    const/16 v1, 0x15

    .line 49
    .line 50
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 51
    .line 52
    .line 53
    sput-object v0, La61/a;->k:La61/a;

    .line 54
    .line 55
    new-instance v0, La61/a;

    .line 56
    .line 57
    const/16 v1, 0x16

    .line 58
    .line 59
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 60
    .line 61
    .line 62
    sput-object v0, La61/a;->l:La61/a;

    .line 63
    .line 64
    new-instance v0, La61/a;

    .line 65
    .line 66
    const/16 v1, 0x17

    .line 67
    .line 68
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 69
    .line 70
    .line 71
    sput-object v0, La61/a;->m:La61/a;

    .line 72
    .line 73
    new-instance v0, La61/a;

    .line 74
    .line 75
    const/16 v1, 0x18

    .line 76
    .line 77
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 78
    .line 79
    .line 80
    sput-object v0, La61/a;->n:La61/a;

    .line 81
    .line 82
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, La61/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lcom/google/firebase/messaging/w;)V
    .locals 0

    const/16 p1, 0xd

    iput p1, p0, La61/a;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static n(Lu/x0;)Landroid/media/MediaCodec;
    .locals 2

    .line 1
    iget-object p0, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lf8/p;

    .line 4
    .line 5
    iget-object p0, p0, Lf8/p;->a:Ljava/lang/String;

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "createCodec:"

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-static {p0}, Landroid/media/MediaCodec;->createByCodecName(Ljava/lang/String;)Landroid/media/MediaCodec;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 29
    .line 30
    .line 31
    return-object p0
.end method

.method public static o(Lwe0/b;)Lus/a;
    .locals 10

    .line 1
    new-instance v3, Lc1/l2;

    .line 2
    .line 3
    const/16 p0, 0x8

    .line 4
    .line 5
    const/4 v0, 0x7

    .line 6
    invoke-direct {v3, p0, v0}, Lc1/l2;-><init>(II)V

    .line 7
    .line 8
    .line 9
    new-instance v4, Lc8/g;

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-direct {v4, p0, v0, v0}, Lc8/g;-><init>(ZZZ)V

    .line 14
    .line 15
    .line 16
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    const p0, 0x36ee80

    .line 21
    .line 22
    .line 23
    int-to-long v5, p0

    .line 24
    add-long v1, v0, v5

    .line 25
    .line 26
    new-instance v0, Lus/a;

    .line 27
    .line 28
    const-wide/high16 v5, 0x4024000000000000L    # 10.0

    .line 29
    .line 30
    const-wide v7, 0x3ff3333333333333L    # 1.2

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    const/16 v9, 0x3c

    .line 36
    .line 37
    invoke-direct/range {v0 .. v9}, Lus/a;-><init>(JLc1/l2;Lc8/g;DDI)V

    .line 38
    .line 39
    .line 40
    return-object v0
.end method

.method public static p(Ljava/lang/String;)Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-static {p0}, Ljava/time/OffsetDateTime;->parse(Ljava/lang/CharSequence;)Ljava/time/OffsetDateTime;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return-object p0
.end method

.method public static q(Ljava/lang/String;)Lss0/p;
    .locals 6

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lss0/p;->values()[Lss0/p;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    array-length v1, v0

    .line 11
    const/4 v2, 0x0

    .line 12
    :goto_0
    if-ge v2, v1, :cond_1

    .line 13
    .line 14
    aget-object v3, v0, v2

    .line 15
    .line 16
    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    sget-object v5, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 21
    .line 22
    invoke-virtual {v4, v5}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    const-string v5, "toUpperCase(...)"

    .line 27
    .line 28
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v4, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_0

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    const/4 v3, 0x0

    .line 42
    :goto_1
    if-nez v3, :cond_2

    .line 43
    .line 44
    sget-object p0, Lss0/p;->t:Lss0/p;

    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_2
    return-object v3
.end method

.method public static r(Ljava/time/OffsetDateTime;)Ljava/lang/String;
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-static {p0}, Lvo/a;->l(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return-object p0
.end method


# virtual methods
.method public a()J
    .locals 2

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public b(Lm6/b;)Ljava/lang/Object;
    .locals 0

    .line 1
    throw p1
.end method

.method public c(Landroid/security/keystore/KeyGenParameterSpec$Builder;)V
    .locals 1

    .line 1
    const-string p0, "GCM"

    .line 2
    .line 3
    filled-new-array {p0}, [Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p1, p0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setBlockModes([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v0, "NoPadding"

    .line 12
    .line 13
    filled-new-array {v0}, [Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {p0, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setEncryptionPaddings([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const/4 v0, 0x1

    .line 22
    invoke-virtual {p0, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setRandomizedEncryptionRequired(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 23
    .line 24
    .line 25
    const/16 p0, 0x100

    .line 26
    .line 27
    invoke-virtual {p1, p0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setKeySize(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public d(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    .locals 0

    .line 1
    return-void
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 4

    .line 1
    const-class p0, Lfv/f;

    .line 2
    .line 3
    new-instance v0, Ldv/a;

    .line 4
    .line 5
    invoke-virtual {p1, p0}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lfv/f;

    .line 10
    .line 11
    const-class p0, Lip/t;

    .line 12
    .line 13
    monitor-enter p0

    .line 14
    const/4 p1, 0x1

    .line 15
    int-to-byte p1, p1

    .line 16
    or-int/lit8 p1, p1, 0x2

    .line 17
    .line 18
    int-to-byte p1, p1

    .line 19
    const/4 v1, 0x3

    .line 20
    if-ne p1, v1, :cond_1

    .line 21
    .line 22
    :try_start_0
    new-instance p1, Lip/o;

    .line 23
    .line 24
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 25
    .line 26
    .line 27
    const-class v1, Lip/t;

    .line 28
    .line 29
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 30
    :try_start_1
    sget-object v2, Lip/t;->a:Lip/s;

    .line 31
    .line 32
    if-nez v2, :cond_0

    .line 33
    .line 34
    new-instance v2, Lip/s;

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    invoke-direct {v2, v3}, Lip/s;-><init>(I)V

    .line 38
    .line 39
    .line 40
    sput-object v2, Lip/t;->a:Lip/s;

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :catchall_0
    move-exception p1

    .line 44
    goto :goto_1

    .line 45
    :cond_0
    :goto_0
    sget-object v2, Lip/t;->a:Lip/s;

    .line 46
    .line 47
    invoke-virtual {v2, p1}, Lap0/o;->y(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    check-cast p1, Lip/r;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 52
    .line 53
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 54
    monitor-exit p0

    .line 55
    const/4 p0, 0x0

    .line 56
    invoke-direct {v0, p0}, Ldv/a;-><init>(I)V

    .line 57
    .line 58
    .line 59
    return-object v0

    .line 60
    :goto_1
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 61
    :try_start_4
    throw p1

    .line 62
    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 65
    .line 66
    .line 67
    and-int/lit8 v1, p1, 0x1

    .line 68
    .line 69
    if-nez v1, :cond_2

    .line 70
    .line 71
    const-string v1, " enableFirelog"

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    :cond_2
    and-int/lit8 p1, p1, 0x2

    .line 77
    .line 78
    if-nez p1, :cond_3

    .line 79
    .line 80
    const-string p1, " firelogEventType"

    .line 81
    .line 82
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    const-string v1, "Missing required properties:"

    .line 92
    .line 93
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw p1

    .line 101
    :goto_2
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 102
    throw p1

    .line 103
    :catchall_1
    move-exception p1

    .line 104
    goto :goto_2
.end method

.method public g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lov/b;

    .line 2
    .line 3
    iget-object p0, p1, Lh/w;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/lang/String;

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const-string p0, ""

    .line 10
    .line 11
    :cond_0
    return-object p0
.end method

.method public get()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {}, Lqt/a;->e()Lqt/a;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lkp/s6;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public h()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, La61/a;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 7
    .line 8
    sget-object p0, Lcom/google/android/gms/internal/measurement/q7;->e:Lcom/google/android/gms/internal/measurement/q7;

    .line 9
    .line 10
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/q7;->d:Lgr/p;

    .line 11
    .line 12
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lcom/google/android/gms/internal/measurement/r7;

    .line 15
    .line 16
    sget-object p0, Lcom/google/android/gms/internal/measurement/s7;->b:Lcom/google/android/gms/internal/measurement/n4;

    .line 17
    .line 18
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Ljava/lang/Boolean;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 29
    .line 30
    sget-object p0, Lcom/google/android/gms/internal/measurement/v9;->e:Lcom/google/android/gms/internal/measurement/v9;

    .line 31
    .line 32
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/v9;->d:Lgr/p;

    .line 33
    .line 34
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lcom/google/android/gms/internal/measurement/w9;

    .line 37
    .line 38
    sget-object p0, Lcom/google/android/gms/internal/measurement/x9;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 39
    .line 40
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Ljava/lang/Boolean;

    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_1
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 51
    .line 52
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 53
    .line 54
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 55
    .line 56
    .line 57
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->W:Lcom/google/android/gms/internal/measurement/n4;

    .line 58
    .line 59
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Ljava/lang/Long;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 66
    .line 67
    .line 68
    move-result-wide v0

    .line 69
    long-to-int p0, v0

    .line 70
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_2
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 76
    .line 77
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 78
    .line 79
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 80
    .line 81
    .line 82
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->j0:Lcom/google/android/gms/internal/measurement/n4;

    .line 83
    .line 84
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    check-cast p0, Ljava/lang/Long;

    .line 89
    .line 90
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 91
    .line 92
    .line 93
    move-result-wide v0

    .line 94
    long-to-int p0, v0

    .line 95
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0

    .line 100
    :pswitch_3
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 101
    .line 102
    sget-object p0, Lcom/google/android/gms/internal/measurement/r8;->e:Lcom/google/android/gms/internal/measurement/r8;

    .line 103
    .line 104
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/r8;->a()Lcom/google/android/gms/internal/measurement/s8;

    .line 105
    .line 106
    .line 107
    sget-object p0, Lcom/google/android/gms/internal/measurement/t8;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 108
    .line 109
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Ljava/lang/Boolean;

    .line 114
    .line 115
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    return-object p0

    .line 119
    :pswitch_4
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 120
    .line 121
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 122
    .line 123
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 124
    .line 125
    .line 126
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->y:Lcom/google/android/gms/internal/measurement/n4;

    .line 127
    .line 128
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    check-cast p0, Ljava/lang/Long;

    .line 133
    .line 134
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    return-object p0

    .line 138
    :pswitch_5
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 139
    .line 140
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 141
    .line 142
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 143
    .line 144
    .line 145
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->P:Lcom/google/android/gms/internal/measurement/n4;

    .line 146
    .line 147
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    check-cast p0, Ljava/lang/Long;

    .line 152
    .line 153
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 154
    .line 155
    .line 156
    move-result-wide v0

    .line 157
    long-to-int p0, v0

    .line 158
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    return-object p0

    .line 163
    :pswitch_6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 164
    .line 165
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 166
    .line 167
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 168
    .line 169
    .line 170
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->k0:Lcom/google/android/gms/internal/measurement/n4;

    .line 171
    .line 172
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    check-cast p0, Ljava/lang/Long;

    .line 177
    .line 178
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 179
    .line 180
    .line 181
    move-result-wide v0

    .line 182
    long-to-int p0, v0

    .line 183
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    return-object p0

    .line 188
    :pswitch_7
    sget-object p0, Lcom/google/android/gms/internal/measurement/n7;->e:Lcom/google/android/gms/internal/measurement/n7;

    .line 189
    .line 190
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/n7;->d:Lgr/p;

    .line 191
    .line 192
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast p0, Lcom/google/android/gms/internal/measurement/o7;

    .line 195
    .line 196
    sget-object p0, Lcom/google/android/gms/internal/measurement/p7;->b:Lcom/google/android/gms/internal/measurement/n4;

    .line 197
    .line 198
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    check-cast p0, Ljava/lang/Boolean;

    .line 203
    .line 204
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 205
    .line 206
    .line 207
    move-result p0

    .line 208
    new-instance v0, Ljava/lang/Boolean;

    .line 209
    .line 210
    invoke-direct {v0, p0}, Ljava/lang/Boolean;-><init>(Z)V

    .line 211
    .line 212
    .line 213
    return-object v0

    .line 214
    nop

    .line 215
    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public j(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    .locals 0

    .line 1
    return-void
.end method

.method public k(Lko/p;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lbq/d;

    .line 2
    .line 3
    return-object p1
.end method

.method public l(Lu/x0;)Lf8/m;
    .locals 4

    .line 1
    const/4 p0, 0x0

    .line 2
    :try_start_0
    invoke-static {p1}, La61/a;->n(Lu/x0;)Landroid/media/MediaCodec;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    const-string v0, "configureCodec"

    .line 7
    .line 8
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p1, Lu/x0;->d:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Landroid/view/Surface;

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    iget-object v1, p1, Lu/x0;->a:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lf8/p;

    .line 20
    .line 21
    iget-boolean v1, v1, Lf8/p;->h:Z

    .line 22
    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 26
    .line 27
    const/16 v2, 0x23

    .line 28
    .line 29
    if-lt v1, v2, :cond_0

    .line 30
    .line 31
    const/16 v1, 0x8

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :catch_0
    move-exception p1

    .line 35
    goto :goto_1

    .line 36
    :cond_0
    const/4 v1, 0x0

    .line 37
    :goto_0
    iget-object v2, p1, Lu/x0;->b:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v2, Landroid/media/MediaFormat;

    .line 40
    .line 41
    iget-object v3, p1, Lu/x0;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v3, Landroid/media/MediaCrypto;

    .line 44
    .line 45
    invoke-virtual {p0, v2, v0, v3, v1}, Landroid/media/MediaCodec;->configure(Landroid/media/MediaFormat;Landroid/view/Surface;Landroid/media/MediaCrypto;I)V

    .line 46
    .line 47
    .line 48
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 49
    .line 50
    .line 51
    const-string v0, "startCodec"

    .line 52
    .line 53
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Landroid/media/MediaCodec;->start()V

    .line 57
    .line 58
    .line 59
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 60
    .line 61
    .line 62
    new-instance v0, Lvp/y1;

    .line 63
    .line 64
    iget-object p1, p1, Lu/x0;->f:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p1, Lgw0/c;

    .line 67
    .line 68
    invoke-direct {v0, p0, p1}, Lvp/y1;-><init>(Landroid/media/MediaCodec;Lgw0/c;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 69
    .line 70
    .line 71
    return-object v0

    .line 72
    :goto_1
    if-eqz p0, :cond_1

    .line 73
    .line 74
    invoke-virtual {p0}, Landroid/media/MediaCodec;->release()V

    .line 75
    .line 76
    .line 77
    :cond_1
    throw p1
.end method

.method public m(Lwe0/b;Lorg/json/JSONObject;)Lus/a;
    .locals 0

    .line 1
    invoke-static {p1}, La61/a;->o(Lwe0/b;)Lus/a;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
