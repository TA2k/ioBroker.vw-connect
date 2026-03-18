.class public final Lh2/v4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Landroidx/compose/material3/a;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Z

.field public final synthetic g:Lc1/n0;

.field public final synthetic h:Ll2/b1;

.field public final synthetic i:Le1/n1;

.field public final synthetic j:Le3/n0;

.field public final synthetic k:J

.field public final synthetic l:F

.field public final synthetic m:F

.field public final synthetic n:Lt2/b;


# direct methods
.method public constructor <init>(Landroidx/compose/material3/a;Lx2/s;ZLc1/n0;Ll2/b1;Le1/n1;Le3/n0;JFFLt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/v4;->d:Landroidx/compose/material3/a;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/v4;->e:Lx2/s;

    .line 7
    .line 8
    iput-boolean p3, p0, Lh2/v4;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lh2/v4;->g:Lc1/n0;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/v4;->h:Ll2/b1;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/v4;->i:Le1/n1;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/v4;->j:Le3/n0;

    .line 17
    .line 18
    iput-wide p8, p0, Lh2/v4;->k:J

    .line 19
    .line 20
    iput p10, p0, Lh2/v4;->l:F

    .line 21
    .line 22
    iput p11, p0, Lh2/v4;->m:F

    .line 23
    .line 24
    iput-object p12, p0, Lh2/v4;->n:Lt2/b;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    check-cast p1, Ll2/o;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    and-int/lit8 v0, p2, 0x3

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    const/4 v2, 0x1

    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    move v0, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    :goto_0
    and-int/2addr p2, v2

    .line 19
    move-object v11, p1

    .line 20
    check-cast v11, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {v11, p2, v0}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-eqz p1, :cond_1

    .line 27
    .line 28
    iget-object p1, p0, Lh2/v4;->d:Landroidx/compose/material3/a;

    .line 29
    .line 30
    check-cast p1, Lh2/x4;

    .line 31
    .line 32
    iget-object p2, p1, Lh2/x4;->j:Ll2/g1;

    .line 33
    .line 34
    iget-object p1, p1, Lh2/x4;->k:Ll2/g1;

    .line 35
    .line 36
    new-instance v0, Ld00/i;

    .line 37
    .line 38
    const/4 v1, 0x3

    .line 39
    iget-boolean v2, p0, Lh2/v4;->f:Z

    .line 40
    .line 41
    invoke-direct {v0, v2, p2, p1, v1}, Ld00/i;-><init>(ZLjava/lang/Object;Ljava/lang/Object;I)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lh2/v4;->e:Lx2/s;

    .line 45
    .line 46
    invoke-static {p1, v0}, Landroidx/compose/ui/layout/a;->b(Lx2/s;Lay0/o;)Lx2/s;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    iget-object v10, p0, Lh2/v4;->n:Lt2/b;

    .line 51
    .line 52
    const/16 v12, 0x180

    .line 53
    .line 54
    iget-object v2, p0, Lh2/v4;->g:Lc1/n0;

    .line 55
    .line 56
    iget-object v3, p0, Lh2/v4;->h:Ll2/b1;

    .line 57
    .line 58
    iget-object v4, p0, Lh2/v4;->i:Le1/n1;

    .line 59
    .line 60
    iget-object v5, p0, Lh2/v4;->j:Le3/n0;

    .line 61
    .line 62
    iget-wide v6, p0, Lh2/v4;->k:J

    .line 63
    .line 64
    iget v8, p0, Lh2/v4;->l:F

    .line 65
    .line 66
    iget v9, p0, Lh2/v4;->m:F

    .line 67
    .line 68
    invoke-static/range {v1 .. v12}, Lh2/q5;->a(Lx2/s;Lc1/n0;Ll2/b1;Le1/n1;Le3/n0;JFFLt2/b;Ll2/o;I)V

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_1
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 73
    .line 74
    .line 75
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0
.end method
