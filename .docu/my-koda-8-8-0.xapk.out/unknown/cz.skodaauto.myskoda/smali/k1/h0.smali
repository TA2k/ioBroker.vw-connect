.class public final synthetic Lk1/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:[I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:[Lt3/e1;

.field public final synthetic i:Lk1/i0;

.field public final synthetic j:I

.field public final synthetic k:Lt4/m;

.field public final synthetic l:I

.field public final synthetic m:[I


# direct methods
.method public synthetic constructor <init>([IIII[Lt3/e1;Lk1/i0;ILt4/m;I[I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk1/h0;->d:[I

    .line 5
    .line 6
    iput p2, p0, Lk1/h0;->e:I

    .line 7
    .line 8
    iput p3, p0, Lk1/h0;->f:I

    .line 9
    .line 10
    iput p4, p0, Lk1/h0;->g:I

    .line 11
    .line 12
    iput-object p5, p0, Lk1/h0;->h:[Lt3/e1;

    .line 13
    .line 14
    iput-object p6, p0, Lk1/h0;->i:Lk1/i0;

    .line 15
    .line 16
    iput p7, p0, Lk1/h0;->j:I

    .line 17
    .line 18
    iput-object p8, p0, Lk1/h0;->k:Lt4/m;

    .line 19
    .line 20
    iput p9, p0, Lk1/h0;->l:I

    .line 21
    .line 22
    iput-object p10, p0, Lk1/h0;->m:[I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    iget-object v0, p0, Lk1/h0;->d:[I

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget v1, p0, Lk1/h0;->e:I

    .line 8
    .line 9
    aget v0, v0, v1

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    :goto_0
    iget v1, p0, Lk1/h0;->f:I

    .line 14
    .line 15
    move v2, v1

    .line 16
    :goto_1
    iget v3, p0, Lk1/h0;->g:I

    .line 17
    .line 18
    if-ge v2, v3, :cond_4

    .line 19
    .line 20
    iget-object v3, p0, Lk1/h0;->h:[Lt3/e1;

    .line 21
    .line 22
    aget-object v3, v3, v2

    .line 23
    .line 24
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v3}, Lt3/e1;->l()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    instance-of v5, v4, Lk1/d1;

    .line 32
    .line 33
    if-eqz v5, :cond_1

    .line 34
    .line 35
    check-cast v4, Lk1/d1;

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_1
    const/4 v4, 0x0

    .line 39
    :goto_2
    if-eqz v4, :cond_2

    .line 40
    .line 41
    iget-object v4, v4, Lk1/d1;->c:Lk1/d;

    .line 42
    .line 43
    if-nez v4, :cond_3

    .line 44
    .line 45
    :cond_2
    iget-object v4, p0, Lk1/h0;->i:Lk1/i0;

    .line 46
    .line 47
    iget-object v4, v4, Lk1/i0;->d:Lk1/x;

    .line 48
    .line 49
    :cond_3
    invoke-virtual {v3}, Lt3/e1;->b0()I

    .line 50
    .line 51
    .line 52
    move-result v5

    .line 53
    iget v6, p0, Lk1/h0;->j:I

    .line 54
    .line 55
    sub-int/2addr v6, v5

    .line 56
    iget-object v5, p0, Lk1/h0;->k:Lt4/m;

    .line 57
    .line 58
    iget v7, p0, Lk1/h0;->l:I

    .line 59
    .line 60
    invoke-virtual {v4, v6, v5, v3, v7}, Lk1/d;->e(ILt4/m;Lt3/e1;I)I

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    add-int/2addr v4, v0

    .line 65
    sub-int v5, v2, v1

    .line 66
    .line 67
    iget-object v6, p0, Lk1/h0;->m:[I

    .line 68
    .line 69
    aget v5, v6, v5

    .line 70
    .line 71
    invoke-static {p1, v3, v5, v4}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 72
    .line 73
    .line 74
    add-int/lit8 v2, v2, 0x1

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 78
    .line 79
    return-object p0
.end method
