.class public final synthetic Lh2/ab;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Double;Ljava/lang/String;Ljava/lang/String;Lg4/p0;JJI)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lh2/ab;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/ab;->h:Ljava/lang/Object;

    iput-object p2, p0, Lh2/ab;->i:Ljava/lang/Object;

    iput-object p3, p0, Lh2/ab;->j:Ljava/lang/Object;

    iput-object p4, p0, Lh2/ab;->k:Ljava/lang/Object;

    iput-wide p5, p0, Lh2/ab;->e:J

    iput-wide p7, p0, Lh2/ab;->f:J

    iput p9, p0, Lh2/ab;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;JJLt2/b;Lt2/b;Lt2/b;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lh2/ab;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/ab;->h:Ljava/lang/Object;

    iput-wide p2, p0, Lh2/ab;->e:J

    iput-wide p4, p0, Lh2/ab;->f:J

    iput-object p6, p0, Lh2/ab;->i:Ljava/lang/Object;

    iput-object p7, p0, Lh2/ab;->j:Ljava/lang/Object;

    iput-object p8, p0, Lh2/ab;->k:Ljava/lang/Object;

    iput p9, p0, Lh2/ab;->g:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lh2/ab;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/ab;->h:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/Double;

    .line 10
    .line 11
    iget-object v0, p0, Lh2/ab;->i:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Ljava/lang/String;

    .line 15
    .line 16
    iget-object v0, p0, Lh2/ab;->j:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v3, v0

    .line 19
    check-cast v3, Ljava/lang/String;

    .line 20
    .line 21
    iget-object v0, p0, Lh2/ab;->k:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v4, v0

    .line 24
    check-cast v4, Lg4/p0;

    .line 25
    .line 26
    move-object v9, p1

    .line 27
    check-cast v9, Ll2/o;

    .line 28
    .line 29
    check-cast p2, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    iget p1, p0, Lh2/ab;->g:I

    .line 35
    .line 36
    or-int/lit8 p1, p1, 0x1

    .line 37
    .line 38
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result v10

    .line 42
    iget-wide v5, p0, Lh2/ab;->e:J

    .line 43
    .line 44
    iget-wide v7, p0, Lh2/ab;->f:J

    .line 45
    .line 46
    invoke-static/range {v1 .. v10}, Ln80/a;->c(Ljava/lang/Double;Ljava/lang/String;Ljava/lang/String;Lg4/p0;JJLl2/o;I)V

    .line 47
    .line 48
    .line 49
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_0
    iget-object v0, p0, Lh2/ab;->h:Ljava/lang/Object;

    .line 53
    .line 54
    move-object v1, v0

    .line 55
    check-cast v1, Lx2/s;

    .line 56
    .line 57
    iget-object v0, p0, Lh2/ab;->i:Ljava/lang/Object;

    .line 58
    .line 59
    move-object v6, v0

    .line 60
    check-cast v6, Lt2/b;

    .line 61
    .line 62
    iget-object v0, p0, Lh2/ab;->j:Ljava/lang/Object;

    .line 63
    .line 64
    move-object v7, v0

    .line 65
    check-cast v7, Lt2/b;

    .line 66
    .line 67
    iget-object v0, p0, Lh2/ab;->k:Ljava/lang/Object;

    .line 68
    .line 69
    move-object v8, v0

    .line 70
    check-cast v8, Lt2/b;

    .line 71
    .line 72
    move-object v9, p1

    .line 73
    check-cast v9, Ll2/o;

    .line 74
    .line 75
    check-cast p2, Ljava/lang/Integer;

    .line 76
    .line 77
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    iget p1, p0, Lh2/ab;->g:I

    .line 81
    .line 82
    or-int/lit8 p1, p1, 0x1

    .line 83
    .line 84
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result v10

    .line 88
    iget-wide v2, p0, Lh2/ab;->e:J

    .line 89
    .line 90
    iget-wide v4, p0, Lh2/ab;->f:J

    .line 91
    .line 92
    invoke-static/range {v1 .. v10}, Lh2/r;->t(Lx2/s;JJLt2/b;Lt2/b;Lt2/b;Ll2/o;I)V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    nop

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
