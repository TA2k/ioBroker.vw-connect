.class public final synthetic Lxk0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lwk0/x1;

.field public final synthetic f:Li91/s2;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lwk0/x1;Li91/s2;Lx2/s;II)V
    .locals 0

    .line 1
    iput p5, p0, Lxk0/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxk0/e;->e:Lwk0/x1;

    .line 4
    .line 5
    iput-object p2, p0, Lxk0/e;->f:Li91/s2;

    .line 6
    .line 7
    iput-object p3, p0, Lxk0/e;->g:Lx2/s;

    .line 8
    .line 9
    iput p4, p0, Lxk0/e;->h:I

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lxk0/e;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lxk0/e;->h:I

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
    iget-object v0, p0, Lxk0/e;->e:Lwk0/x1;

    .line 22
    .line 23
    iget-object v1, p0, Lxk0/e;->f:Li91/s2;

    .line 24
    .line 25
    iget-object p0, p0, Lxk0/e;->g:Lx2/s;

    .line 26
    .line 27
    invoke-static {v0, v1, p0, p1, p2}, Lxk0/h;->I(Lwk0/x1;Li91/s2;Lx2/s;Ll2/o;I)V

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
    iget p2, p0, Lxk0/e;->h:I

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
    iget-object v0, p0, Lxk0/e;->e:Lwk0/x1;

    .line 42
    .line 43
    iget-object v1, p0, Lxk0/e;->f:Li91/s2;

    .line 44
    .line 45
    iget-object p0, p0, Lxk0/e;->g:Lx2/s;

    .line 46
    .line 47
    invoke-static {v0, v1, p0, p1, p2}, Lxk0/h;->t0(Lwk0/x1;Li91/s2;Lx2/s;Ll2/o;I)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :pswitch_1
    iget p2, p0, Lxk0/e;->h:I

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
    iget-object v0, p0, Lxk0/e;->e:Lwk0/x1;

    .line 60
    .line 61
    iget-object v1, p0, Lxk0/e;->f:Li91/s2;

    .line 62
    .line 63
    iget-object p0, p0, Lxk0/e;->g:Lx2/s;

    .line 64
    .line 65
    invoke-static {v0, v1, p0, p1, p2}, Lxk0/h;->s0(Lwk0/x1;Li91/s2;Lx2/s;Ll2/o;I)V

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
