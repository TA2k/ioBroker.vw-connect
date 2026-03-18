.class public final synthetic Lws/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lws/c;


# direct methods
.method public synthetic constructor <init>(Lws/c;I)V
    .locals 0

    .line 1
    iput p2, p0, Lws/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lws/a;->e:Lws/c;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lws/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v2, p1

    .line 7
    check-cast v2, Landroid/content/Context;

    .line 8
    .line 9
    const-string p1, "it"

    .line 10
    .line 11
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lws/a;->e:Lws/c;

    .line 15
    .line 16
    iget-object v3, p0, Lws/c;->a:Ljava/lang/String;

    .line 17
    .line 18
    sget-object p0, Lp6/j;->a:Ljava/util/LinkedHashSet;

    .line 19
    .line 20
    const-string p1, "sharedPreferencesName"

    .line 21
    .line 22
    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string p1, "keysToMigrate"

    .line 26
    .line 27
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    new-instance v1, Lo6/c;

    .line 31
    .line 32
    new-instance v5, La7/r0;

    .line 33
    .line 34
    const/4 p1, 0x1

    .line 35
    const/4 v0, 0x0

    .line 36
    invoke-direct {v5, p0, v0, p1}, La7/r0;-><init>(Ljava/util/Set;Lkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    new-instance v6, Lal0/y0;

    .line 40
    .line 41
    const/4 p0, 0x3

    .line 42
    const/16 p1, 0x12

    .line 43
    .line 44
    invoke-direct {v6, p0, v0, p1}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    sget-object v4, Lo6/d;->a:Ljava/util/LinkedHashSet;

    .line 48
    .line 49
    invoke-direct/range {v1 .. v6}, Lo6/c;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/util/Set;La7/r0;Lal0/y0;)V

    .line 50
    .line 51
    .line 52
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_0
    check-cast p1, Lm6/b;

    .line 58
    .line 59
    const-string v0, "ex"

    .line 60
    .line 61
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const-class v0, Lws/c;

    .line 65
    .line 66
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 67
    .line 68
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    invoke-interface {v0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    new-instance v1, Ljava/lang/StringBuilder;

    .line 77
    .line 78
    const-string v2, "CorruptionException in "

    .line 79
    .line 80
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    iget-object p0, p0, Lws/a;->e:Lws/c;

    .line 84
    .line 85
    iget-object p0, p0, Lws/c;->a:Ljava/lang/String;

    .line 86
    .line 87
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string p0, " DataStore running in process "

    .line 91
    .line 92
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-static {}, Landroid/os/Process;->myPid()I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-static {v0, p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 107
    .line 108
    .line 109
    new-instance p0, Lq6/b;

    .line 110
    .line 111
    const/4 p1, 0x1

    .line 112
    invoke-direct {p0, p1}, Lq6/b;-><init>(Z)V

    .line 113
    .line 114
    .line 115
    return-object p0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
