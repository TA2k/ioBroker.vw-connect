.class public final synthetic Lf2/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:J

.field public final synthetic g:F

.field public final synthetic h:F

.field public final synthetic i:I

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;JFFIII)V
    .locals 0

    .line 1
    iput p8, p0, Lf2/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf2/v;->e:Lx2/s;

    .line 4
    .line 5
    iput-wide p2, p0, Lf2/v;->f:J

    .line 6
    .line 7
    iput p4, p0, Lf2/v;->g:F

    .line 8
    .line 9
    iput p5, p0, Lf2/v;->h:F

    .line 10
    .line 11
    iput p6, p0, Lf2/v;->i:I

    .line 12
    .line 13
    iput p7, p0, Lf2/v;->j:I

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lf2/v;->d:I

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
    iget p1, p0, Lf2/v;->i:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v7

    .line 22
    iget-object v1, p0, Lf2/v;->e:Lx2/s;

    .line 23
    .line 24
    iget-wide v2, p0, Lf2/v;->f:J

    .line 25
    .line 26
    iget v4, p0, Lf2/v;->g:F

    .line 27
    .line 28
    iget v5, p0, Lf2/v;->h:F

    .line 29
    .line 30
    iget v8, p0, Lf2/v;->j:I

    .line 31
    .line 32
    invoke-static/range {v1 .. v8}, Lxf0/y1;->r(Lx2/s;JFFLl2/o;II)V

    .line 33
    .line 34
    .line 35
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_0
    move-object v5, p1

    .line 39
    check-cast v5, Ll2/o;

    .line 40
    .line 41
    check-cast p2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    iget p1, p0, Lf2/v;->i:I

    .line 47
    .line 48
    or-int/lit8 p1, p1, 0x1

    .line 49
    .line 50
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result v6

    .line 54
    iget-object v0, p0, Lf2/v;->e:Lx2/s;

    .line 55
    .line 56
    iget-wide v1, p0, Lf2/v;->f:J

    .line 57
    .line 58
    iget v3, p0, Lf2/v;->g:F

    .line 59
    .line 60
    iget v4, p0, Lf2/v;->h:F

    .line 61
    .line 62
    iget v7, p0, Lf2/v;->j:I

    .line 63
    .line 64
    invoke-static/range {v0 .. v7}, Lkp/d7;->a(Lx2/s;JFFLl2/o;II)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
