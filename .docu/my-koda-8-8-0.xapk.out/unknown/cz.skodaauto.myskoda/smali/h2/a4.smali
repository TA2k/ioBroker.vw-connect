.class public final synthetic Lh2/a4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/g4;


# direct methods
.method public synthetic constructor <init>(Lh2/g4;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/a4;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/a4;->e:Lh2/g4;

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
    .locals 3

    .line 1
    iget v0, p0, Lh2/a4;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Long;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iget-object p0, p0, Lh2/a4;->e:Lh2/g4;

    .line 13
    .line 14
    invoke-virtual {p0, v0, v1}, Lh2/s;->b(J)V

    .line 15
    .line 16
    .line 17
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    check-cast p1, Lh2/o4;

    .line 21
    .line 22
    iget p1, p1, Lh2/o4;->a:I

    .line 23
    .line 24
    iget-object p0, p0, Lh2/a4;->e:Lh2/g4;

    .line 25
    .line 26
    invoke-virtual {p0}, Lh2/g4;->h()Ljava/lang/Long;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 33
    .line 34
    .line 35
    move-result-wide v0

    .line 36
    iget-object v2, p0, Lh2/s;->c:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v2, Li2/b0;

    .line 39
    .line 40
    invoke-virtual {v2, v0, v1}, Li2/b0;->b(J)Li2/c0;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    iget-wide v0, v0, Li2/c0;->e:J

    .line 45
    .line 46
    invoke-virtual {p0, v0, v1}, Lh2/s;->b(J)V

    .line 47
    .line 48
    .line 49
    :cond_0
    iget-object p0, p0, Lh2/g4;->h:Ll2/j1;

    .line 50
    .line 51
    new-instance v0, Lh2/o4;

    .line 52
    .line 53
    invoke-direct {v0, p1}, Lh2/o4;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
