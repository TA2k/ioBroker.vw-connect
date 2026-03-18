.class public final Lh2/ga;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/n;

.field public final synthetic e:Lt2/b;

.field public final synthetic f:Lay0/n;

.field public final synthetic g:Lg4/p0;

.field public final synthetic h:J

.field public final synthetic i:J


# direct methods
.method public constructor <init>(Lay0/n;Lt2/b;Lay0/n;Lg4/p0;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/ga;->d:Lay0/n;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/ga;->e:Lt2/b;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/ga;->f:Lay0/n;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/ga;->g:Lg4/p0;

    .line 11
    .line 12
    iput-wide p5, p0, Lh2/ga;->h:J

    .line 13
    .line 14
    iput-wide p7, p0, Lh2/ga;->i:J

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x1

    .line 19
    const/4 v6, 0x0

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v5

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v6

    .line 25
    :goto_0
    and-int/2addr v2, v5

    .line 26
    move-object v15, v1

    .line 27
    check-cast v15, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v15, v2, v3}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    const v1, -0xa1260e1

    .line 36
    .line 37
    .line 38
    invoke-virtual {v15, v1}, Ll2/t;->Y(I)V

    .line 39
    .line 40
    .line 41
    iget-wide v13, v0, Lh2/ga;->i:J

    .line 42
    .line 43
    const/16 v16, 0x0

    .line 44
    .line 45
    iget-object v7, v0, Lh2/ga;->e:Lt2/b;

    .line 46
    .line 47
    iget-object v8, v0, Lh2/ga;->d:Lay0/n;

    .line 48
    .line 49
    iget-object v9, v0, Lh2/ga;->f:Lay0/n;

    .line 50
    .line 51
    iget-object v10, v0, Lh2/ga;->g:Lg4/p0;

    .line 52
    .line 53
    iget-wide v11, v0, Lh2/ga;->h:J

    .line 54
    .line 55
    invoke-static/range {v7 .. v16}, Lh2/ja;->a(Lt2/b;Lay0/n;Lay0/n;Lg4/p0;JJLl2/o;I)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 63
    .line 64
    .line 65
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    return-object v0
.end method
