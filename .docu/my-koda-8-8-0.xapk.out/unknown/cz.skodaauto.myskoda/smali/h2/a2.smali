.class public final synthetic Lh2/a2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lay0/a;JLh2/k6;Lc1/c;Lt2/b;I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lh2/a2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/a2;->g:Ljava/lang/Object;

    iput-wide p2, p0, Lh2/a2;->e:J

    iput-object p4, p0, Lh2/a2;->h:Ljava/lang/Object;

    iput-object p5, p0, Lh2/a2;->i:Ljava/lang/Object;

    iput-object p6, p0, Lh2/a2;->j:Ljava/lang/Object;

    iput p7, p0, Lh2/a2;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Lh2/c2;Ljava/lang/Long;ILh2/g2;Lx2/s;JI)V
    .locals 0

    .line 2
    const/4 p8, 0x0

    iput p8, p0, Lh2/a2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/a2;->g:Ljava/lang/Object;

    iput-object p2, p0, Lh2/a2;->h:Ljava/lang/Object;

    iput p3, p0, Lh2/a2;->f:I

    iput-object p4, p0, Lh2/a2;->i:Ljava/lang/Object;

    iput-object p5, p0, Lh2/a2;->j:Ljava/lang/Object;

    iput-wide p6, p0, Lh2/a2;->e:J

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lh2/a2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/a2;->g:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lay0/a;

    .line 10
    .line 11
    iget-object v0, p0, Lh2/a2;->h:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v4, v0

    .line 14
    check-cast v4, Lh2/k6;

    .line 15
    .line 16
    iget-object v0, p0, Lh2/a2;->i:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v5, v0

    .line 19
    check-cast v5, Lc1/c;

    .line 20
    .line 21
    iget-object v0, p0, Lh2/a2;->j:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v6, v0

    .line 24
    check-cast v6, Lt2/b;

    .line 25
    .line 26
    move-object v7, p1

    .line 27
    check-cast v7, Ll2/o;

    .line 28
    .line 29
    check-cast p2, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    iget p1, p0, Lh2/a2;->f:I

    .line 35
    .line 36
    or-int/lit8 p1, p1, 0x1

    .line 37
    .line 38
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result v8

    .line 42
    iget-wide v2, p0, Lh2/a2;->e:J

    .line 43
    .line 44
    invoke-static/range {v1 .. v8}, Lh2/r;->n(Lay0/a;JLh2/k6;Lc1/c;Lt2/b;Ll2/o;I)V

    .line 45
    .line 46
    .line 47
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_0
    iget-object v0, p0, Lh2/a2;->g:Ljava/lang/Object;

    .line 51
    .line 52
    move-object v1, v0

    .line 53
    check-cast v1, Lh2/c2;

    .line 54
    .line 55
    iget-object v0, p0, Lh2/a2;->h:Ljava/lang/Object;

    .line 56
    .line 57
    move-object v2, v0

    .line 58
    check-cast v2, Ljava/lang/Long;

    .line 59
    .line 60
    iget-object v0, p0, Lh2/a2;->i:Ljava/lang/Object;

    .line 61
    .line 62
    move-object v4, v0

    .line 63
    check-cast v4, Lh2/g2;

    .line 64
    .line 65
    iget-object v0, p0, Lh2/a2;->j:Ljava/lang/Object;

    .line 66
    .line 67
    move-object v5, v0

    .line 68
    check-cast v5, Lx2/s;

    .line 69
    .line 70
    move-object v8, p1

    .line 71
    check-cast v8, Ll2/o;

    .line 72
    .line 73
    check-cast p2, Ljava/lang/Integer;

    .line 74
    .line 75
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    const p1, 0x30c01

    .line 79
    .line 80
    .line 81
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 82
    .line 83
    .line 84
    move-result v9

    .line 85
    iget v3, p0, Lh2/a2;->f:I

    .line 86
    .line 87
    iget-wide v6, p0, Lh2/a2;->e:J

    .line 88
    .line 89
    invoke-virtual/range {v1 .. v9}, Lh2/c2;->a(Ljava/lang/Long;ILh2/g2;Lx2/s;JLl2/o;I)V

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
