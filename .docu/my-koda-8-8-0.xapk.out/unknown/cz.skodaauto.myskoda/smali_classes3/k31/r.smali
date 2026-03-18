.class public final Lk31/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr41/a;


# instance fields
.field public final a:Lk31/n;

.field public final b:Lk31/b0;

.field public final c:Lk31/z;

.field public final d:Lk31/h;


# direct methods
.method public constructor <init>(Lk31/n;Lk31/b0;Lk31/z;Lk31/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk31/r;->a:Lk31/n;

    .line 5
    .line 6
    iput-object p2, p0, Lk31/r;->b:Lk31/b0;

    .line 7
    .line 8
    iput-object p3, p0, Lk31/r;->c:Lk31/z;

    .line 9
    .line 10
    iput-object p4, p0, Lk31/r;->d:Lk31/h;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lk31/p;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lk31/r;->a:Lk31/n;

    .line 9
    .line 10
    invoke-virtual {v0}, Lk31/n;->a()Li31/j;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object v0, v0, Li31/j;->e:Li31/g;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v0, 0x0

    .line 20
    :goto_0
    if-nez v0, :cond_1

    .line 21
    .line 22
    const/4 v0, -0x1

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    sget-object v1, Lk31/q;->a:[I

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    aget v0, v1, v0

    .line 31
    .line 32
    :goto_1
    const/4 v1, 0x1

    .line 33
    const/4 v2, 0x0

    .line 34
    if-eq v0, v1, :cond_4

    .line 35
    .line 36
    const/4 v1, 0x2

    .line 37
    if-eq v0, v1, :cond_3

    .line 38
    .line 39
    const/4 v1, 0x3

    .line 40
    if-eq v0, v1, :cond_2

    .line 41
    .line 42
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    new-instance v0, Lk31/g;

    .line 46
    .line 47
    invoke-direct {v0, v2}, Lk31/g;-><init>(Lz70/d;)V

    .line 48
    .line 49
    .line 50
    iget-object p0, p0, Lk31/r;->d:Lk31/h;

    .line 51
    .line 52
    invoke-virtual {p0, v0}, Lk31/h;->a(Lk31/g;)Ljava/util/List;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    goto :goto_2

    .line 57
    :cond_3
    new-instance v0, Lk31/y;

    .line 58
    .line 59
    invoke-direct {v0, v2}, Lk31/y;-><init>(Lz70/d;)V

    .line 60
    .line 61
    .line 62
    iget-object p0, p0, Lk31/r;->c:Lk31/z;

    .line 63
    .line 64
    invoke-virtual {p0, v0}, Lk31/z;->a(Lk31/y;)Ljava/util/ArrayList;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    goto :goto_2

    .line 69
    :cond_4
    new-instance v0, Lk31/a0;

    .line 70
    .line 71
    invoke-direct {v0, v2}, Lk31/a0;-><init>(Lz70/d;)V

    .line 72
    .line 73
    .line 74
    iget-object p0, p0, Lk31/r;->b:Lk31/b0;

    .line 75
    .line 76
    invoke-virtual {p0, v0}, Lk31/b0;->a(Lk31/a0;)Ljava/util/ArrayList;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    :goto_2
    return-object p0
.end method
