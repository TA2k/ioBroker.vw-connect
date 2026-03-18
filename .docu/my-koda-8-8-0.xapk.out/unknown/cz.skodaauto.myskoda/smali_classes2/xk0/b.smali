.class public final synthetic Lxk0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li91/s2;

.field public final synthetic f:Lwk0/x1;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(Li91/s2;Lwk0/x1;Lay0/k;Lay0/k;I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lxk0/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxk0/b;->e:Li91/s2;

    iput-object p2, p0, Lxk0/b;->f:Lwk0/x1;

    iput-object p3, p0, Lxk0/b;->g:Lay0/k;

    iput-object p4, p0, Lxk0/b;->h:Lay0/k;

    iput p5, p0, Lxk0/b;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Lwk0/x1;Li91/s2;Lay0/k;Lay0/k;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lxk0/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxk0/b;->f:Lwk0/x1;

    iput-object p2, p0, Lxk0/b;->e:Li91/s2;

    iput-object p3, p0, Lxk0/b;->g:Lay0/k;

    iput-object p4, p0, Lxk0/b;->h:Lay0/k;

    iput p5, p0, Lxk0/b;->i:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lxk0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Lxk0/b;->i:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    iget-object v2, p0, Lxk0/b;->g:Lay0/k;

    .line 23
    .line 24
    iget-object v3, p0, Lxk0/b;->h:Lay0/k;

    .line 25
    .line 26
    iget-object v4, p0, Lxk0/b;->e:Li91/s2;

    .line 27
    .line 28
    iget-object v6, p0, Lxk0/b;->f:Lwk0/x1;

    .line 29
    .line 30
    invoke-static/range {v1 .. v6}, Lxk0/h;->N(ILay0/k;Lay0/k;Li91/s2;Ll2/o;Lwk0/x1;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    move-object v4, p1

    .line 37
    check-cast v4, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 42
    .line 43
    .line 44
    iget p1, p0, Lxk0/b;->i:I

    .line 45
    .line 46
    or-int/lit8 p1, p1, 0x1

    .line 47
    .line 48
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object v1, p0, Lxk0/b;->g:Lay0/k;

    .line 53
    .line 54
    iget-object v2, p0, Lxk0/b;->h:Lay0/k;

    .line 55
    .line 56
    iget-object v3, p0, Lxk0/b;->e:Li91/s2;

    .line 57
    .line 58
    iget-object v5, p0, Lxk0/b;->f:Lwk0/x1;

    .line 59
    .line 60
    invoke-static/range {v0 .. v5}, Lxk0/d;->a(ILay0/k;Lay0/k;Li91/s2;Ll2/o;Lwk0/x1;)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
