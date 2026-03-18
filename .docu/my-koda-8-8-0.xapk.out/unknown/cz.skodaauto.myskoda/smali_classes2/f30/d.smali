.class public final synthetic Lf30/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Le30/h;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Z

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:I

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(Le30/h;Lx2/s;ZLay0/a;Lay0/a;III)V
    .locals 0

    .line 1
    iput p8, p0, Lf30/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf30/d;->e:Le30/h;

    .line 4
    .line 5
    iput-object p2, p0, Lf30/d;->f:Lx2/s;

    .line 6
    .line 7
    iput-boolean p3, p0, Lf30/d;->g:Z

    .line 8
    .line 9
    iput-object p4, p0, Lf30/d;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Lf30/d;->i:Lay0/a;

    .line 12
    .line 13
    iput p6, p0, Lf30/d;->j:I

    .line 14
    .line 15
    iput p7, p0, Lf30/d;->k:I

    .line 16
    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lf30/d;->d:I

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
    iget p1, p0, Lf30/d;->j:I

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
    iget-object v1, p0, Lf30/d;->e:Le30/h;

    .line 23
    .line 24
    iget-object v2, p0, Lf30/d;->f:Lx2/s;

    .line 25
    .line 26
    iget-boolean v3, p0, Lf30/d;->g:Z

    .line 27
    .line 28
    iget-object v4, p0, Lf30/d;->h:Lay0/a;

    .line 29
    .line 30
    iget-object v5, p0, Lf30/d;->i:Lay0/a;

    .line 31
    .line 32
    iget v8, p0, Lf30/d;->k:I

    .line 33
    .line 34
    invoke-static/range {v1 .. v8}, Lf30/a;->h(Le30/h;Lx2/s;ZLay0/a;Lay0/a;Ll2/o;II)V

    .line 35
    .line 36
    .line 37
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    move-object v5, p1

    .line 41
    check-cast v5, Ll2/o;

    .line 42
    .line 43
    check-cast p2, Ljava/lang/Integer;

    .line 44
    .line 45
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    iget p1, p0, Lf30/d;->j:I

    .line 49
    .line 50
    or-int/lit8 p1, p1, 0x1

    .line 51
    .line 52
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 53
    .line 54
    .line 55
    move-result v6

    .line 56
    iget-object v0, p0, Lf30/d;->e:Le30/h;

    .line 57
    .line 58
    iget-object v1, p0, Lf30/d;->f:Lx2/s;

    .line 59
    .line 60
    iget-boolean v2, p0, Lf30/d;->g:Z

    .line 61
    .line 62
    iget-object v3, p0, Lf30/d;->h:Lay0/a;

    .line 63
    .line 64
    iget-object v4, p0, Lf30/d;->i:Lay0/a;

    .line 65
    .line 66
    iget v7, p0, Lf30/d;->k:I

    .line 67
    .line 68
    invoke-static/range {v0 .. v7}, Lf30/a;->h(Le30/h;Lx2/s;ZLay0/a;Lay0/a;Ll2/o;II)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
