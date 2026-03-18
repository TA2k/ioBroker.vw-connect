.class public final synthetic Li91/d3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:Lx2/s;


# direct methods
.method public synthetic constructor <init>(JJLx2/s;I)V
    .locals 0

    .line 1
    const/4 p6, 0x1

    iput p6, p0, Li91/d3;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Li91/d3;->e:J

    iput-wide p3, p0, Li91/d3;->f:J

    iput-object p5, p0, Li91/d3;->g:Lx2/s;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;JJII)V
    .locals 0

    .line 2
    iput p7, p0, Li91/d3;->d:I

    iput-object p1, p0, Li91/d3;->g:Lx2/s;

    iput-wide p2, p0, Li91/d3;->e:J

    iput-wide p4, p0, Li91/d3;->f:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Li91/d3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v6, p1

    .line 7
    check-cast v6, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    iget-wide v2, p0, Li91/d3;->e:J

    .line 20
    .line 21
    iget-wide v4, p0, Li91/d3;->f:J

    .line 22
    .line 23
    iget-object v7, p0, Li91/d3;->g:Lx2/s;

    .line 24
    .line 25
    invoke-static/range {v1 .. v7}, Ln70/a;->R(IJJLl2/o;Lx2/s;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    move-object v5, p1

    .line 32
    check-cast v5, Ll2/o;

    .line 33
    .line 34
    check-cast p2, Ljava/lang/Integer;

    .line 35
    .line 36
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    const/16 p1, 0x181

    .line 40
    .line 41
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    iget-wide v1, p0, Li91/d3;->e:J

    .line 46
    .line 47
    iget-wide v3, p0, Li91/d3;->f:J

    .line 48
    .line 49
    iget-object v6, p0, Li91/d3;->g:Lx2/s;

    .line 50
    .line 51
    invoke-static/range {v0 .. v6}, Ln70/a;->Q(IJJLl2/o;Lx2/s;)V

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :pswitch_1
    move-object v5, p1

    .line 56
    check-cast v5, Ll2/o;

    .line 57
    .line 58
    check-cast p2, Ljava/lang/Integer;

    .line 59
    .line 60
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    const/4 p1, 0x1

    .line 64
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget-wide v1, p0, Li91/d3;->e:J

    .line 69
    .line 70
    iget-wide v3, p0, Li91/d3;->f:J

    .line 71
    .line 72
    iget-object v6, p0, Li91/d3;->g:Lx2/s;

    .line 73
    .line 74
    invoke-static/range {v0 .. v6}, Li91/j0;->U(IJJLl2/o;Lx2/s;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
