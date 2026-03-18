.class public final Lg1/u1;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lb0/d1;

.field public e:Lkotlin/jvm/internal/f0;

.field public f:Lkotlin/jvm/internal/c0;

.field public g:Lg1/u2;

.field public h:Lkotlin/jvm/internal/f0;

.field public synthetic i:Ljava/lang/Object;

.field public j:I


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iput-object p1, p0, Lg1/u1;->i:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lg1/u1;->j:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lg1/u1;->j:I

    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    const-wide/16 v5, 0x0

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    const/4 v1, 0x0

    .line 15
    const/4 v2, 0x0

    .line 16
    const/4 v3, 0x0

    .line 17
    move-object v7, p0

    .line 18
    invoke-static/range {v0 .. v7}, Lb0/d1;->b(Lb0/d1;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/c0;Lg1/u2;Lkotlin/jvm/internal/f0;JLrx0/c;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
