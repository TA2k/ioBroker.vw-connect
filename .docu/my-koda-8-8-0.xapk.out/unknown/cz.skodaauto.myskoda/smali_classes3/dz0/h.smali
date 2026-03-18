.class public abstract Ldz0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lj51/i;

.field public static final b:Lj51/i;

.field public static final c:Lj51/i;

.field public static final d:Lj51/i;

.field public static final e:Lj51/i;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lj51/i;

    .line 2
    .line 3
    const-string v1, "STATE_REG"

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ldz0/h;->a:Lj51/i;

    .line 10
    .line 11
    new-instance v0, Lj51/i;

    .line 12
    .line 13
    const-string v1, "STATE_COMPLETED"

    .line 14
    .line 15
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 16
    .line 17
    .line 18
    sput-object v0, Ldz0/h;->b:Lj51/i;

    .line 19
    .line 20
    new-instance v0, Lj51/i;

    .line 21
    .line 22
    const-string v1, "STATE_CANCELLED"

    .line 23
    .line 24
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Ldz0/h;->c:Lj51/i;

    .line 28
    .line 29
    new-instance v0, Lj51/i;

    .line 30
    .line 31
    const-string v1, "NO_RESULT"

    .line 32
    .line 33
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 34
    .line 35
    .line 36
    sput-object v0, Ldz0/h;->d:Lj51/i;

    .line 37
    .line 38
    new-instance v0, Lj51/i;

    .line 39
    .line 40
    const-string v1, "PARAM_CLAUSE_0"

    .line 41
    .line 42
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 43
    .line 44
    .line 45
    sput-object v0, Ldz0/h;->e:Lj51/i;

    .line 46
    .line 47
    return-void
.end method

.method public static final a(Ldz0/e;JLay0/k;)V
    .locals 8

    .line 1
    new-instance v2, Ldz0/b;

    .line 2
    .line 3
    invoke-direct {v2, p1, p2}, Ldz0/b;-><init>(J)V

    .line 4
    .line 5
    .line 6
    sget-object v3, Ldz0/a;->d:Ldz0/a;

    .line 7
    .line 8
    const/4 p1, 0x3

    .line 9
    invoke-static {p1, v3}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    new-instance v0, Ldz0/c;

    .line 13
    .line 14
    sget-object v5, Ldz0/h;->e:Lj51/i;

    .line 15
    .line 16
    move-object v6, p3

    .line 17
    check-cast v6, Lrx0/i;

    .line 18
    .line 19
    sget-object v4, Ldz0/g;->d:Ldz0/g;

    .line 20
    .line 21
    const/4 v7, 0x0

    .line 22
    move-object v1, p0

    .line 23
    invoke-direct/range {v0 .. v7}, Ldz0/c;-><init>(Ldz0/e;Ljava/lang/Object;Lay0/o;Lay0/o;Lj51/i;Lrx0/i;Lay0/o;)V

    .line 24
    .line 25
    .line 26
    sget-object p0, Ldz0/e;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    invoke-virtual {v1, v0, p0}, Ldz0/e;->g(Ldz0/c;Z)V

    .line 30
    .line 31
    .line 32
    return-void
.end method
