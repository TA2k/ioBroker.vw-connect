.class public final synthetic Lc00/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/p;


# direct methods
.method public synthetic constructor <init>(Lc00/p;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc00/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/i;->e:Lc00/p;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lc00/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lc00/i;->e:Lc00/p;

    .line 7
    .line 8
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lc00/n;

    .line 13
    .line 14
    iget-object v1, p0, Lc00/p;->l:Lij0/a;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-static {v0, v1, v2}, Ljp/xb;->x(Lc00/n;Lij0/a;Ljava/lang/Boolean;)Lc00/n;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 22
    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_0
    new-instance v0, Llj0/a;

    .line 28
    .line 29
    iget-object p0, p0, Lc00/i;->e:Lc00/p;

    .line 30
    .line 31
    iget-object p0, p0, Lc00/p;->l:Lij0/a;

    .line 32
    .line 33
    const v1, 0x7f120084

    .line 34
    .line 35
    .line 36
    check-cast p0, Ljj0/f;

    .line 37
    .line 38
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
