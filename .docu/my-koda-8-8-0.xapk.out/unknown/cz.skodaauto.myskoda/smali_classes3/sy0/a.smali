.class public final Lsy0/a;
.super Landroidx/collection/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lby0/d;


# instance fields
.field public final g:Lj3/f0;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lj3/f0;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "parentIterator"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    invoke-direct {p0, v0, p2, p3}, Landroidx/collection/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lsy0/a;->g:Lj3/f0;

    .line 11
    .line 12
    iput-object p3, p0, Lsy0/a;->h:Ljava/lang/Object;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lsy0/a;->h:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setValue(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lsy0/a;->h:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p1, p0, Lsy0/a;->h:Ljava/lang/Object;

    .line 4
    .line 5
    iget-object v1, p0, Lsy0/a;->g:Lj3/f0;

    .line 6
    .line 7
    iget-object v1, v1, Lj3/f0;->e:Ljava/util/Iterator;

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lsy0/e;

    .line 11
    .line 12
    iget-object v1, v2, Lsy0/e;->h:Lsy0/d;

    .line 13
    .line 14
    iget-object p0, p0, Landroidx/collection/x;->e:Ljava/lang/Object;

    .line 15
    .line 16
    invoke-virtual {v1, p0}, Lsy0/d;->containsKey(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-nez v3, :cond_0

    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_0
    iget-boolean v3, v2, Lq2/c;->f:Z

    .line 24
    .line 25
    if-eqz v3, :cond_3

    .line 26
    .line 27
    if-eqz v3, :cond_2

    .line 28
    .line 29
    iget-object v3, v2, Lq2/c;->g:[Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v3, [Lq2/j;

    .line 32
    .line 33
    iget v4, v2, Lq2/c;->e:I

    .line 34
    .line 35
    aget-object v3, v3, v4

    .line 36
    .line 37
    iget-object v4, v3, Lq2/j;->e:[Ljava/lang/Object;

    .line 38
    .line 39
    iget v3, v3, Lq2/j;->g:I

    .line 40
    .line 41
    aget-object v5, v4, v3

    .line 42
    .line 43
    invoke-virtual {v1, p0, p1}, Lsy0/d;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    if-eqz v5, :cond_1

    .line 47
    .line 48
    invoke-virtual {v5}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    :goto_0
    move v3, p0

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    const/4 p0, 0x0

    .line 55
    goto :goto_0

    .line 56
    :goto_1
    iget-object v4, v1, Lsy0/d;->f:Lsy0/j;

    .line 57
    .line 58
    const/4 v7, 0x0

    .line 59
    const/4 v8, 0x0

    .line 60
    const/4 v6, 0x0

    .line 61
    invoke-virtual/range {v2 .. v8}, Lsy0/e;->e(ILsy0/j;Ljava/lang/Object;IIZ)V

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_2
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 66
    .line 67
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_3
    invoke-virtual {v1, p0, p1}, Lsy0/d;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    :goto_2
    iget p0, v1, Lsy0/d;->h:I

    .line 75
    .line 76
    iput p0, v2, Lsy0/e;->k:I

    .line 77
    .line 78
    return-object v0
.end method
