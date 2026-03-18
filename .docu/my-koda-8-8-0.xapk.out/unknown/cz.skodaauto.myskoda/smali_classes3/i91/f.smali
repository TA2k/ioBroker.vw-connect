.class public final synthetic Li91/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lt2/b;

.field public final synthetic f:Lay0/n;

.field public final synthetic g:F


# direct methods
.method public synthetic constructor <init>(ZLt2/b;Lt2/b;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Li91/f;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Li91/f;->e:Lt2/b;

    .line 7
    .line 8
    iput-object p3, p0, Li91/f;->f:Lay0/n;

    .line 9
    .line 10
    iput p4, p0, Li91/f;->g:F

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Ljava/lang/Float;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    check-cast p2, Ll2/o;

    .line 8
    .line 9
    check-cast p3, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result p3

    .line 15
    and-int/lit8 v0, p3, 0x6

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    move-object v0, p2

    .line 20
    check-cast v0, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ll2/t;->d(F)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v0, 0x2

    .line 31
    :goto_0
    or-int/2addr p3, v0

    .line 32
    :cond_1
    and-int/lit8 v0, p3, 0x13

    .line 33
    .line 34
    const/16 v1, 0x12

    .line 35
    .line 36
    const/4 v2, 0x1

    .line 37
    if-eq v0, v1, :cond_2

    .line 38
    .line 39
    move v0, v2

    .line 40
    goto :goto_1

    .line 41
    :cond_2
    const/4 v0, 0x0

    .line 42
    :goto_1
    and-int/2addr p3, v2

    .line 43
    move-object v5, p2

    .line 44
    check-cast v5, Ll2/t;

    .line 45
    .line 46
    invoke-virtual {v5, p3, v0}, Ll2/t;->O(IZ)Z

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    if-eqz p2, :cond_4

    .line 51
    .line 52
    iget-boolean p2, p0, Li91/f;->d:Z

    .line 53
    .line 54
    if-eqz p2, :cond_3

    .line 55
    .line 56
    const/high16 p1, 0x3f800000    # 1.0f

    .line 57
    .line 58
    :cond_3
    move v3, p1

    .line 59
    const/4 v6, 0x0

    .line 60
    iget-object v1, p0, Li91/f;->e:Lt2/b;

    .line 61
    .line 62
    iget-object v2, p0, Li91/f;->f:Lay0/n;

    .line 63
    .line 64
    iget v4, p0, Li91/f;->g:F

    .line 65
    .line 66
    invoke-static/range {v1 .. v6}, Li91/j0;->m(Lt2/b;Lay0/n;FFLl2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_4
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    return-object p0
.end method
