.class public final synthetic Lbl/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc3/j;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lc3/j;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbl/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbl/e;->e:Lc3/j;

    .line 4
    .line 5
    iput-object p2, p0, Lbl/e;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lbl/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lbl/e;->e:Lc3/j;

    .line 7
    .line 8
    invoke-static {v0}, Lc3/j;->a(Lc3/j;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lwc/b;->a:Lwc/b;

    .line 12
    .line 13
    iget-object p0, p0, Lbl/e;->f:Lay0/k;

    .line 14
    .line 15
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_0
    iget-object v0, p0, Lbl/e;->e:Lc3/j;

    .line 22
    .line 23
    invoke-static {v0}, Lc3/j;->a(Lc3/j;)V

    .line 24
    .line 25
    .line 26
    sget-object v0, Lnh/o;->a:Lnh/o;

    .line 27
    .line 28
    iget-object p0, p0, Lbl/e;->f:Lay0/k;

    .line 29
    .line 30
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
