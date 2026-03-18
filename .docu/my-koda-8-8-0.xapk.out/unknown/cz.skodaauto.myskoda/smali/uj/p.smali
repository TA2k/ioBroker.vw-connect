.class public final synthetic Luj/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Luj/q;

.field public final synthetic f:Llc/q;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Luj/q;Llc/q;Lay0/k;II)V
    .locals 0

    .line 1
    iput p5, p0, Luj/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luj/p;->e:Luj/q;

    .line 4
    .line 5
    iput-object p2, p0, Luj/p;->f:Llc/q;

    .line 6
    .line 7
    iput-object p3, p0, Luj/p;->g:Lay0/k;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Luj/p;->d:I

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
    const/16 p2, 0x9

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, Luj/p;->e:Luj/q;

    .line 20
    .line 21
    iget-object v1, p0, Luj/p;->f:Llc/q;

    .line 22
    .line 23
    iget-object p0, p0, Luj/p;->g:Lay0/k;

    .line 24
    .line 25
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/q;->U(Llc/q;Lay0/k;Ll2/o;I)V

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
    const/16 p2, 0x9

    .line 32
    .line 33
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 34
    .line 35
    .line 36
    move-result p2

    .line 37
    iget-object v0, p0, Luj/p;->e:Luj/q;

    .line 38
    .line 39
    iget-object v1, p0, Luj/p;->f:Llc/q;

    .line 40
    .line 41
    iget-object p0, p0, Luj/p;->g:Lay0/k;

    .line 42
    .line 43
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/q;->r(Llc/q;Lay0/k;Ll2/o;I)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :pswitch_1
    const/16 p2, 0x9

    .line 48
    .line 49
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 50
    .line 51
    .line 52
    move-result p2

    .line 53
    iget-object v0, p0, Luj/p;->e:Luj/q;

    .line 54
    .line 55
    iget-object v1, p0, Luj/p;->f:Llc/q;

    .line 56
    .line 57
    iget-object p0, p0, Luj/p;->g:Lay0/k;

    .line 58
    .line 59
    invoke-virtual {v0, v1, p0, p1, p2}, Luj/q;->D0(Llc/q;Lay0/k;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
