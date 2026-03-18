.class public abstract Lns/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lha/c;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lha/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lha/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lns/a;->a:Lha/c;

    .line 8
    .line 9
    return-void
.end method

.method public static a(Laq/j;Laq/j;)Laq/t;
    .locals 5

    .line 1
    new-instance v0, Laq/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Laq/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Laq/k;

    .line 8
    .line 9
    iget-object v2, v0, Laq/a;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, La0/j;

    .line 12
    .line 13
    invoke-direct {v1, v2}, Laq/k;-><init>(La0/j;)V

    .line 14
    .line 15
    .line 16
    new-instance v2, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    invoke-direct {v2, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 20
    .line 21
    .line 22
    new-instance v3, Lbb/i;

    .line 23
    .line 24
    const/16 v4, 0x9

    .line 25
    .line 26
    invoke-direct {v3, v1, v2, v0, v4}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    sget-object v0, Lns/a;->a:Lha/c;

    .line 30
    .line 31
    invoke-virtual {p0, v0, v3}, Laq/j;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1, v0, v3}, Laq/j;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 35
    .line 36
    .line 37
    iget-object p0, v1, Laq/k;->a:Laq/t;

    .line 38
    .line 39
    return-object p0
.end method
