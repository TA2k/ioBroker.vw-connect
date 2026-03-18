.class public final synthetic Lal/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Llh/g;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Llh/g;Lay0/k;Lx2/s;I)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lal/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lal/h;->f:Llh/g;

    iput-object p2, p0, Lal/h;->g:Lay0/k;

    iput-object p3, p0, Lal/h;->e:Lx2/s;

    iput p4, p0, Lal/h;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Llh/g;Lay0/k;II)V
    .locals 0

    .line 2
    iput p5, p0, Lal/h;->d:I

    iput-object p1, p0, Lal/h;->e:Lx2/s;

    iput-object p2, p0, Lal/h;->f:Llh/g;

    iput-object p3, p0, Lal/h;->g:Lay0/k;

    iput p4, p0, Lal/h;->h:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lal/h;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lal/h;->h:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object v0, p0, Lal/h;->g:Lay0/k;

    .line 22
    .line 23
    iget-object v1, p0, Lal/h;->f:Llh/g;

    .line 24
    .line 25
    iget-object p0, p0, Lal/h;->e:Lx2/s;

    .line 26
    .line 27
    invoke-static {p2, v0, p1, v1, p0}, Lwk/a;->j(ILay0/k;Ll2/o;Llh/g;Lx2/s;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_0
    iget p2, p0, Lal/h;->h:I

    .line 34
    .line 35
    or-int/lit8 p2, p2, 0x1

    .line 36
    .line 37
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    iget-object v0, p0, Lal/h;->g:Lay0/k;

    .line 42
    .line 43
    iget-object v1, p0, Lal/h;->f:Llh/g;

    .line 44
    .line 45
    iget-object p0, p0, Lal/h;->e:Lx2/s;

    .line 46
    .line 47
    invoke-static {p2, v0, p1, v1, p0}, Lwk/a;->e(ILay0/k;Ll2/o;Llh/g;Lx2/s;)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :pswitch_1
    iget p2, p0, Lal/h;->h:I

    .line 52
    .line 53
    or-int/lit8 p2, p2, 0x1

    .line 54
    .line 55
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    iget-object v0, p0, Lal/h;->g:Lay0/k;

    .line 60
    .line 61
    iget-object v1, p0, Lal/h;->f:Llh/g;

    .line 62
    .line 63
    iget-object p0, p0, Lal/h;->e:Lx2/s;

    .line 64
    .line 65
    invoke-static {p2, v0, p1, v1, p0}, Lal/a;->b(ILay0/k;Ll2/o;Llh/g;Lx2/s;)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
