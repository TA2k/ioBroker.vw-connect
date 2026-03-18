.class public final synthetic Le2/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt1/w0;


# direct methods
.method public synthetic constructor <init>(Lt1/w0;I)V
    .locals 0

    .line 1
    iput p2, p0, Le2/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le2/v;->e:Lt1/w0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Le2/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ld3/b;

    .line 7
    .line 8
    iget-wide v0, p1, Ld3/b;->a:J

    .line 9
    .line 10
    iget-object p0, p0, Le2/v;->e:Lt1/w0;

    .line 11
    .line 12
    invoke-interface {p0, v0, v1}, Lt1/w0;->b(J)V

    .line 13
    .line 14
    .line 15
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    check-cast p1, Lp3/t;

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-static {p1, v0}, Lp3/s;->h(Lp3/t;Z)J

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    iget-object p0, p0, Le2/v;->e:Lt1/w0;

    .line 26
    .line 27
    invoke-interface {p0, v0, v1}, Lt1/w0;->e(J)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p1}, Lp3/t;->a()V

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
