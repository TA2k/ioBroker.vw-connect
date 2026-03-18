.class public final Lvy0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field public final a:[Lvy0/h0;

.field private volatile synthetic notCompletedCount$volatile:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lvy0/e;

    .line 2
    .line 3
    const-string v1, "notCompletedCount$volatile"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lvy0/e;->b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>([Lvy0/h0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvy0/e;->a:[Lvy0/h0;

    .line 5
    .line 6
    array-length p1, p1

    .line 7
    iput p1, p0, Lvy0/e;->notCompletedCount$volatile:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    new-instance v0, Lvy0/l;

    .line 2
    .line 3
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, v1, p1}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lvy0/l;->q()V

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lvy0/e;->a:[Lvy0/h0;

    .line 15
    .line 16
    array-length v2, p1

    .line 17
    new-array v3, v2, [Lvy0/c;

    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    move v5, v4

    .line 21
    :goto_0
    if-ge v5, v2, :cond_0

    .line 22
    .line 23
    aget-object v6, p1, v5

    .line 24
    .line 25
    move-object v7, v6

    .line 26
    check-cast v7, Lvy0/p1;

    .line 27
    .line 28
    invoke-virtual {v7}, Lvy0/p1;->start()Z

    .line 29
    .line 30
    .line 31
    new-instance v7, Lvy0/c;

    .line 32
    .line 33
    invoke-direct {v7, p0, v0}, Lvy0/c;-><init>(Lvy0/e;Lvy0/l;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v6, v1, v7}, Lvy0/e0;->z(Lvy0/i1;ZLvy0/l1;)Lvy0/r0;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    iput-object v6, v7, Lvy0/c;->i:Lvy0/r0;

    .line 41
    .line 42
    aput-object v7, v3, v5

    .line 43
    .line 44
    add-int/lit8 v5, v5, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    new-instance p0, Lvy0/d;

    .line 48
    .line 49
    invoke-direct {p0, v3}, Lvy0/d;-><init>([Lvy0/c;)V

    .line 50
    .line 51
    .line 52
    :goto_1
    if-ge v4, v2, :cond_1

    .line 53
    .line 54
    aget-object p1, v3, v4

    .line 55
    .line 56
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    sget-object v1, Lvy0/c;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 60
    .line 61
    invoke-virtual {v1, p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    add-int/lit8 v4, v4, 0x1

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_1
    invoke-virtual {v0}, Lvy0/l;->x()Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-eqz p1, :cond_2

    .line 72
    .line 73
    invoke-virtual {p0}, Lvy0/d;->b()V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_2
    invoke-virtual {v0, p0}, Lvy0/l;->u(Lvy0/v1;)V

    .line 78
    .line 79
    .line 80
    :goto_2
    invoke-virtual {v0}, Lvy0/l;->p()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 85
    .line 86
    return-object p0
.end method
