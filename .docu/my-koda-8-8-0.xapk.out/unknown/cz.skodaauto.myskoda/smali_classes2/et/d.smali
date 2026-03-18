.class public final Let/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ler/h;
.implements Lpx0/f;
.implements Loa/a;
.implements Lgs/e;
.implements Lkx0/a;
.implements Lvp/u;
.implements Lmy0/b;
.implements Lxo/a;


# static fields
.field public static e:Let/d;

.field public static final synthetic f:Let/d;

.field public static final synthetic g:Let/d;

.field public static final synthetic h:Let/d;

.field public static final synthetic i:Let/d;

.field public static final synthetic j:Let/d;

.field public static final synthetic k:Let/d;

.field public static final synthetic l:Let/d;

.field public static final synthetic m:Let/d;

.field public static final synthetic n:Let/d;

.field public static final synthetic o:Let/d;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Let/d;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Let/d;->f:Let/d;

    .line 9
    .line 10
    new-instance v0, Let/d;

    .line 11
    .line 12
    const/16 v1, 0x11

    .line 13
    .line 14
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Let/d;->g:Let/d;

    .line 18
    .line 19
    new-instance v0, Let/d;

    .line 20
    .line 21
    const/16 v1, 0x12

    .line 22
    .line 23
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Let/d;->h:Let/d;

    .line 27
    .line 28
    new-instance v0, Let/d;

    .line 29
    .line 30
    const/16 v1, 0x13

    .line 31
    .line 32
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Let/d;->i:Let/d;

    .line 36
    .line 37
    new-instance v0, Let/d;

    .line 38
    .line 39
    const/16 v1, 0x14

    .line 40
    .line 41
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Let/d;->j:Let/d;

    .line 45
    .line 46
    new-instance v0, Let/d;

    .line 47
    .line 48
    const/16 v1, 0x15

    .line 49
    .line 50
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Let/d;->k:Let/d;

    .line 54
    .line 55
    new-instance v0, Let/d;

    .line 56
    .line 57
    const/16 v1, 0x16

    .line 58
    .line 59
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 60
    .line 61
    .line 62
    sput-object v0, Let/d;->l:Let/d;

    .line 63
    .line 64
    new-instance v0, Let/d;

    .line 65
    .line 66
    const/16 v1, 0x17

    .line 67
    .line 68
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Let/d;->m:Let/d;

    .line 72
    .line 73
    new-instance v0, Let/d;

    .line 74
    .line 75
    const/16 v1, 0x18

    .line 76
    .line 77
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Let/d;->n:Let/d;

    .line 81
    .line 82
    new-instance v0, Let/d;

    .line 83
    .line 84
    const/16 v1, 0x1a

    .line 85
    .line 86
    invoke-direct {v0, v1}, Let/d;-><init>(I)V

    .line 87
    .line 88
    .line 89
    sput-object v0, Let/d;->o:Let/d;

    .line 90
    .line 91
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Let/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ld01/x;)V
    .locals 1

    const/16 v0, 0x1b

    iput v0, p0, Let/d;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    const-class p0, Landroidx/camera/camera2/internal/compat/quirk/UseTorchAsFlashQuirk;

    invoke-virtual {p1, p0}, Ld01/x;->k(Ljava/lang/Class;)Z

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Let/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static b(Ljava/lang/String;Lk4/x;I)Landroid/graphics/Typeface;
    .locals 2

    .line 1
    if-nez p2, :cond_1

    .line 2
    .line 3
    sget-object v0, Lk4/x;->l:Lk4/x;

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    :cond_0
    sget-object p0, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    const/4 v0, 0x0

    .line 23
    if-nez p0, :cond_2

    .line 24
    .line 25
    sget-object p0, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_2
    invoke-static {p0, v0}, Landroid/graphics/Typeface;->create(Ljava/lang/String;I)Landroid/graphics/Typeface;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    :goto_0
    iget p1, p1, Lk4/x;->d:I

    .line 33
    .line 34
    const/4 v1, 0x1

    .line 35
    if-ne p2, v1, :cond_3

    .line 36
    .line 37
    move v0, v1

    .line 38
    :cond_3
    invoke-static {p0, p1, v0}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;IZ)Landroid/graphics/Typeface;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

.method public static c(Ljava/lang/String;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x5

    .line 3
    invoke-static {v1, p0, v0}, Let/d;->g(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static d(Ljava/lang/String;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x2

    .line 3
    invoke-static {v1, p0, v0}, Let/d;->g(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static f(Lon0/h;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x5

    .line 11
    if-eq p0, v0, :cond_0

    .line 12
    .line 13
    const/4 v0, 0x7

    .line 14
    if-eq p0, v0, :cond_0

    .line 15
    .line 16
    const/16 v0, 0x8

    .line 17
    .line 18
    if-eq p0, v0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    return p0

    .line 22
    :cond_0
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method public static g(ILjava/lang/String;Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    const-string v0, "severity"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lia/b;->q(ILjava/lang/String;)V

    .line 4
    .line 5
    .line 6
    packed-switch p0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    throw p0

    .line 11
    :pswitch_0
    const/4 p0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :pswitch_1
    const/4 p0, 0x2

    .line 14
    goto :goto_0

    .line 15
    :pswitch_2
    const/4 p0, 0x3

    .line 16
    goto :goto_0

    .line 17
    :pswitch_3
    const/4 p0, 0x4

    .line 18
    goto :goto_0

    .line 19
    :pswitch_4
    const/4 p0, 0x5

    .line 20
    goto :goto_0

    .line 21
    :pswitch_5
    const/4 p0, 0x6

    .line 22
    goto :goto_0

    .line 23
    :pswitch_6
    const p0, 0x7fffffff

    .line 24
    .line 25
    .line 26
    :goto_0
    const/4 v0, 0x4

    .line 27
    if-lt p0, v0, :cond_3

    .line 28
    .line 29
    :try_start_0
    const-string v0, "Phrase OTA"

    .line 30
    .line 31
    if-eqz p1, :cond_0

    .line 32
    .line 33
    if-eqz p2, :cond_0

    .line 34
    .line 35
    new-instance v1, Ljava/lang/StringBuilder;

    .line 36
    .line 37
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const/16 p1, 0xa

    .line 44
    .line 45
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-static {p2}, Loa0/b;->b(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    goto :goto_1

    .line 60
    :cond_0
    if-nez p1, :cond_2

    .line 61
    .line 62
    if-eqz p2, :cond_1

    .line 63
    .line 64
    invoke-static {p2}, Loa0/b;->b(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    goto :goto_1

    .line 69
    :cond_1
    const-string p1, "<null>"

    .line 70
    .line 71
    :cond_2
    :goto_1
    const/4 p2, 0x2

    .line 72
    invoke-static {p2, p0}, Ljava/lang/Math;->max(II)I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    invoke-static {p0, v0, p1}, Landroid/util/Log;->println(ILjava/lang/String;Ljava/lang/String;)I

    .line 77
    .line 78
    .line 79
    sget-object p0, Llx0/b0;->a:Llx0/b0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :catchall_0
    move-exception p0

    .line 83
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-eqz p0, :cond_3

    .line 92
    .line 93
    invoke-static {p0}, Loa0/b;->b(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    const-string p1, "[Phrase OTA Logger] Error while invoking the actual Logger\n"

    .line 98
    .line 99
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    sget-object p1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 104
    .line 105
    invoke-virtual {p1, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    :cond_3
    return-void

    .line 109
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public synthetic a()Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p0, Ler/p;

    .line 2
    .line 3
    const-string v0, "IntegrityService"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ler/p;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Let/d;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Lpv/f;

    .line 7
    .line 8
    const-class v0, Lfv/f;

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Lfv/f;

    .line 15
    .line 16
    invoke-direct {p0, p1}, Lpv/f;-><init>(Lfv/f;)V

    .line 17
    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    new-instance p0, Llv/d;

    .line 21
    .line 22
    const-class v0, Lfv/f;

    .line 23
    .line 24
    invoke-virtual {p1, v0}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Lfv/f;

    .line 29
    .line 30
    invoke-direct {p0, p1}, Llv/d;-><init>(Lfv/f;)V

    .line 31
    .line 32
    .line 33
    return-object p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_0
    .end packed-switch
.end method

.method public get()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/firebase/perf/session/SessionManager;->getInstance()Lcom/google/firebase/perf/session/SessionManager;

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
    iget p0, p0, Let/d;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 7
    .line 8
    sget-object p0, Lcom/google/android/gms/internal/measurement/b7;->e:Lcom/google/android/gms/internal/measurement/b7;

    .line 9
    .line 10
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/b7;->d:Lgr/p;

    .line 11
    .line 12
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lcom/google/android/gms/internal/measurement/c7;

    .line 15
    .line 16
    sget-object p0, Lcom/google/android/gms/internal/measurement/d7;->a:Lcom/google/android/gms/internal/measurement/n4;

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
    sget-object p0, Lcom/google/android/gms/internal/measurement/w7;->e:Lcom/google/android/gms/internal/measurement/w7;

    .line 31
    .line 32
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/w7;->d:Lgr/p;

    .line 33
    .line 34
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lcom/google/android/gms/internal/measurement/x7;

    .line 37
    .line 38
    sget-object p0, Lcom/google/android/gms/internal/measurement/y7;->a:Lcom/google/android/gms/internal/measurement/n4;

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
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->w:Lcom/google/android/gms/internal/measurement/n4;

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
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->p:Lcom/google/android/gms/internal/measurement/n4;

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
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 103
    .line 104
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 105
    .line 106
    .line 107
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->g:Lcom/google/android/gms/internal/measurement/n4;

    .line 108
    .line 109
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Ljava/lang/String;

    .line 114
    .line 115
    return-object p0

    .line 116
    :pswitch_4
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 117
    .line 118
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 119
    .line 120
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 121
    .line 122
    .line 123
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->F:Lcom/google/android/gms/internal/measurement/n4;

    .line 124
    .line 125
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    check-cast p0, Ljava/lang/Long;

    .line 130
    .line 131
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    return-object p0

    .line 135
    :pswitch_5
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 136
    .line 137
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 138
    .line 139
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 140
    .line 141
    .line 142
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->S:Lcom/google/android/gms/internal/measurement/n4;

    .line 143
    .line 144
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    check-cast p0, Ljava/lang/Long;

    .line 149
    .line 150
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    return-object p0

    .line 154
    :pswitch_6
    sget-object p0, Lvp/z;->a:Ljava/util/List;

    .line 155
    .line 156
    sget-object p0, Lcom/google/android/gms/internal/measurement/h7;->e:Lcom/google/android/gms/internal/measurement/h7;

    .line 157
    .line 158
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/h7;->a()Lcom/google/android/gms/internal/measurement/i7;

    .line 159
    .line 160
    .line 161
    sget-object p0, Lcom/google/android/gms/internal/measurement/j7;->r:Lcom/google/android/gms/internal/measurement/n4;

    .line 162
    .line 163
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    check-cast p0, Ljava/lang/Long;

    .line 168
    .line 169
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 170
    .line 171
    .line 172
    move-result-wide v0

    .line 173
    long-to-int p0, v0

    .line 174
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    return-object p0

    .line 179
    :pswitch_7
    sget-object p0, Lcom/google/android/gms/internal/measurement/c8;->e:Lcom/google/android/gms/internal/measurement/c8;

    .line 180
    .line 181
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/c8;->d:Lgr/p;

    .line 182
    .line 183
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast p0, Lcom/google/android/gms/internal/measurement/d8;

    .line 186
    .line 187
    sget-object p0, Lcom/google/android/gms/internal/measurement/e8;->a:Lcom/google/android/gms/internal/measurement/n4;

    .line 188
    .line 189
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/n4;->b()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    check-cast p0, Ljava/lang/Boolean;

    .line 194
    .line 195
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 196
    .line 197
    .line 198
    move-result p0

    .line 199
    new-instance v0, Ljava/lang/Boolean;

    .line 200
    .line 201
    invoke-direct {v0, p0}, Ljava/lang/Boolean;-><init>(Z)V

    .line 202
    .line 203
    .line 204
    return-object v0

    .line 205
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

.method public l(Landroidx/sqlite/db/SupportSQLiteDatabase;)V
    .locals 0

    .line 1
    const-string p0, "db"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "UPDATE WorkSpec SET `last_enqueue_time` = -1 WHERE `last_enqueue_time` = 0"

    .line 7
    .line 8
    invoke-interface {p1, p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public now()Lmy0/f;
    .locals 10

    .line 1
    sget-object p0, Lmy0/f;->f:Lmy0/f;

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const-wide/16 v2, 0x3e8

    .line 8
    .line 9
    div-long v4, v0, v2

    .line 10
    .line 11
    xor-long v6, v0, v2

    .line 12
    .line 13
    const-wide/16 v8, 0x0

    .line 14
    .line 15
    cmp-long p0, v6, v8

    .line 16
    .line 17
    if-gez p0, :cond_0

    .line 18
    .line 19
    mul-long v6, v4, v2

    .line 20
    .line 21
    cmp-long p0, v6, v0

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    const-wide/16 v6, -0x1

    .line 26
    .line 27
    add-long/2addr v4, v6

    .line 28
    :cond_0
    rem-long/2addr v0, v2

    .line 29
    xor-long v6, v0, v2

    .line 30
    .line 31
    neg-long v8, v0

    .line 32
    or-long/2addr v8, v0

    .line 33
    and-long/2addr v6, v8

    .line 34
    const/16 p0, 0x3f

    .line 35
    .line 36
    shr-long/2addr v6, p0

    .line 37
    and-long/2addr v2, v6

    .line 38
    add-long/2addr v0, v2

    .line 39
    const p0, 0xf4240

    .line 40
    .line 41
    .line 42
    int-to-long v2, p0

    .line 43
    mul-long/2addr v0, v2

    .line 44
    long-to-int p0, v0

    .line 45
    const-wide v0, -0x701cefeb9bec00L

    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    cmp-long v0, v4, v0

    .line 51
    .line 52
    if-gez v0, :cond_1

    .line 53
    .line 54
    sget-object p0, Lmy0/f;->f:Lmy0/f;

    .line 55
    .line 56
    return-object p0

    .line 57
    :cond_1
    const-wide v0, 0x701cd2fa9578ffL

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    cmp-long v0, v4, v0

    .line 63
    .line 64
    if-lez v0, :cond_2

    .line 65
    .line 66
    sget-object p0, Lmy0/f;->g:Lmy0/f;

    .line 67
    .line 68
    return-object p0

    .line 69
    :cond_2
    invoke-static {p0, v4, v5}, Lmy0/h;->i(IJ)Lmy0/f;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0
.end method

.method public synthetic o(Landroid/os/Bundle;)Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method
