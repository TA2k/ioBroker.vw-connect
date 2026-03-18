.class public final Lsr/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgs/e;


# static fields
.field public static final e:Lsr/g;

.field public static final f:Lsr/g;

.field public static final g:Lsr/g;

.field public static final h:Lsr/g;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lsr/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lsr/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lsr/g;->e:Lsr/g;

    .line 8
    .line 9
    new-instance v0, Lsr/g;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lsr/g;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lsr/g;->f:Lsr/g;

    .line 16
    .line 17
    new-instance v0, Lsr/g;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lsr/g;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lsr/g;->g:Lsr/g;

    .line 24
    .line 25
    new-instance v0, Lsr/g;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lsr/g;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lsr/g;->h:Lsr/g;

    .line 32
    .line 33
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lsr/g;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final e(Lin/z1;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lsr/g;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Lgs/s;

    .line 7
    .line 8
    const-class v0, Lyr/d;

    .line 9
    .line 10
    const-class v1, Ljava/util/concurrent/Executor;

    .line 11
    .line 12
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, p0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const-string p1, "get(...)"

    .line 20
    .line 21
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    check-cast p0, Ljava/util/concurrent/Executor;

    .line 25
    .line 26
    invoke-static {p0}, Lvy0/e0;->t(Ljava/util/concurrent/Executor;)Lvy0/x;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_0
    new-instance p0, Lgs/s;

    .line 32
    .line 33
    const-class v0, Lyr/b;

    .line 34
    .line 35
    const-class v1, Ljava/util/concurrent/Executor;

    .line 36
    .line 37
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1, p0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    const-string p1, "get(...)"

    .line 45
    .line 46
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    check-cast p0, Ljava/util/concurrent/Executor;

    .line 50
    .line 51
    invoke-static {p0}, Lvy0/e0;->t(Ljava/util/concurrent/Executor;)Lvy0/x;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_1
    new-instance p0, Lgs/s;

    .line 57
    .line 58
    const-class v0, Lyr/c;

    .line 59
    .line 60
    const-class v1, Ljava/util/concurrent/Executor;

    .line 61
    .line 62
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1, p0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-string p1, "get(...)"

    .line 70
    .line 71
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    check-cast p0, Ljava/util/concurrent/Executor;

    .line 75
    .line 76
    invoke-static {p0}, Lvy0/e0;->t(Ljava/util/concurrent/Executor;)Lvy0/x;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_2
    new-instance p0, Lgs/s;

    .line 82
    .line 83
    const-class v0, Lyr/a;

    .line 84
    .line 85
    const-class v1, Ljava/util/concurrent/Executor;

    .line 86
    .line 87
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p1, p0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    const-string p1, "get(...)"

    .line 95
    .line 96
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    check-cast p0, Ljava/util/concurrent/Executor;

    .line 100
    .line 101
    invoke-static {p0}, Lvy0/e0;->t(Ljava/util/concurrent/Executor;)Lvy0/x;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    return-object p0

    .line 106
    nop

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
