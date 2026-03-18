.class public abstract Lrd0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    sget-object v0, Lss0/f;->v:Lss0/f;

    .line 2
    .line 3
    sget-object v1, Lss0/f;->l:Lss0/f;

    .line 4
    .line 5
    sget-object v2, Lss0/f;->k:Lss0/f;

    .line 6
    .line 7
    sget-object v3, Lss0/f;->n:Lss0/f;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lss0/f;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lrd0/c;->a:Ljava/util/List;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(Lss0/b;)Z
    .locals 1

    .line 1
    sget-object v0, Lss0/e;->s:Lss0/e;

    .line 2
    .line 3
    invoke-static {p0, v0}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Lss0/e;->M:Lss0/e;

    .line 10
    .line 11
    invoke-static {p0, v0}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method
