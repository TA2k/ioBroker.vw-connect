.class public final Lhw0/f;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lkw0/c;

.field public e:Ljava/lang/Object;

.field public f:Low0/e;

.field public g:Ljava/util/List;

.field public h:Ljava/util/Iterator;

.field public i:Lhw0/a;

.field public synthetic j:Ljava/lang/Object;

.field public k:I


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iput-object p1, p0, Lhw0/f;->j:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lhw0/f;->k:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lhw0/f;->k:I

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v4, 0x0

    .line 12
    const/4 v0, 0x0

    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x0

    .line 15
    move-object v5, p0

    .line 16
    invoke-static/range {v0 .. v5}, Lhw0/h;->a(Ljava/util/List;Ljava/util/Set;Lgw0/b;Lkw0/c;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
