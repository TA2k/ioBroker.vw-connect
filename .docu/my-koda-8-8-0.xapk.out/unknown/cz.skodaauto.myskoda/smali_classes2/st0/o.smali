.class public abstract Lst0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/List;

.field public static final b:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    sget-object v0, Lss0/f;->A:Lss0/f;

    .line 2
    .line 3
    sget-object v1, Lss0/f;->n:Lss0/f;

    .line 4
    .line 5
    sget-object v2, Lss0/f;->z:Lss0/f;

    .line 6
    .line 7
    sget-object v3, Lss0/f;->h:Lss0/f;

    .line 8
    .line 9
    sget-object v4, Lss0/f;->g:Lss0/f;

    .line 10
    .line 11
    sget-object v5, Lss0/f;->i:Lss0/f;

    .line 12
    .line 13
    filled-new-array/range {v0 .. v5}, [Lss0/f;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lst0/o;->a:Ljava/util/List;

    .line 22
    .line 23
    sget-object v1, Lss0/f;->l:Lss0/f;

    .line 24
    .line 25
    sget-object v2, Lss0/f;->e:Lss0/f;

    .line 26
    .line 27
    sget-object v3, Lss0/f;->f:Lss0/f;

    .line 28
    .line 29
    sget-object v4, Lss0/f;->d:Lss0/f;

    .line 30
    .line 31
    sget-object v5, Lss0/f;->m:Lss0/f;

    .line 32
    .line 33
    sget-object v6, Lss0/f;->j:Lss0/f;

    .line 34
    .line 35
    sget-object v7, Lss0/f;->v:Lss0/f;

    .line 36
    .line 37
    filled-new-array/range {v1 .. v7}, [Lss0/f;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lst0/o;->b:Ljava/util/List;

    .line 46
    .line 47
    return-void
.end method

.method public static final a(Lss0/b;)Z
    .locals 3

    .line 1
    sget-object v0, Lss0/e;->d:Lss0/e;

    .line 2
    .line 3
    sget-object v1, Lst0/o;->a:Ljava/util/List;

    .line 4
    .line 5
    check-cast v1, Ljava/util/Collection;

    .line 6
    .line 7
    sget-object v2, Lst0/o;->b:Ljava/util/List;

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Iterable;

    .line 10
    .line 11
    invoke-static {v2, v1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-static {p0, v0, v1}, Llp/pf;->f(Lss0/b;Lss0/e;Ljava/util/List;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method
