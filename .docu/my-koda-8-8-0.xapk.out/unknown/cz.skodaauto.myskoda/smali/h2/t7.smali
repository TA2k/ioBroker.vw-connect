.class public final synthetic Lh2/t7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/u7;


# direct methods
.method public synthetic constructor <init>(Lh2/u7;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/t7;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/t7;->e:Lh2/u7;

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
    .locals 4

    .line 1
    iget v0, p0, Lh2/t7;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lt4/l;

    .line 7
    .line 8
    iget-wide v0, p1, Lt4/l;->a:J

    .line 9
    .line 10
    const/16 v2, 0x20

    .line 11
    .line 12
    shr-long/2addr v0, v2

    .line 13
    long-to-int v0, v0

    .line 14
    int-to-float v0, v0

    .line 15
    iget-object p0, p0, Lh2/t7;->e:Lh2/u7;

    .line 16
    .line 17
    iget-object v1, p0, Lh2/u7;->j:Ll2/f1;

    .line 18
    .line 19
    invoke-virtual {v1, v0}, Ll2/f1;->p(F)V

    .line 20
    .line 21
    .line 22
    iget-wide v0, p1, Lt4/l;->a:J

    .line 23
    .line 24
    const-wide v2, 0xffffffffL

    .line 25
    .line 26
    .line 27
    .line 28
    .line 29
    and-long/2addr v0, v2

    .line 30
    long-to-int p1, v0

    .line 31
    int-to-float p1, p1

    .line 32
    iget-object p0, p0, Lh2/u7;->k:Ll2/f1;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

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
    check-cast p1, Lt4/l;

    .line 41
    .line 42
    iget-wide v0, p1, Lt4/l;->a:J

    .line 43
    .line 44
    const/16 v2, 0x20

    .line 45
    .line 46
    shr-long/2addr v0, v2

    .line 47
    long-to-int v0, v0

    .line 48
    int-to-float v0, v0

    .line 49
    iget-object p0, p0, Lh2/t7;->e:Lh2/u7;

    .line 50
    .line 51
    iget-object v1, p0, Lh2/u7;->h:Ll2/f1;

    .line 52
    .line 53
    invoke-virtual {v1, v0}, Ll2/f1;->p(F)V

    .line 54
    .line 55
    .line 56
    iget-wide v0, p1, Lt4/l;->a:J

    .line 57
    .line 58
    const-wide v2, 0xffffffffL

    .line 59
    .line 60
    .line 61
    .line 62
    .line 63
    and-long/2addr v0, v2

    .line 64
    long-to-int p1, v0

    .line 65
    int-to-float p1, p1

    .line 66
    iget-object p0, p0, Lh2/u7;->i:Ll2/f1;

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :pswitch_1
    check-cast p1, Ljava/lang/Boolean;

    .line 73
    .line 74
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lh2/t7;->e:Lh2/u7;

    .line 78
    .line 79
    iget-object p0, p0, Lh2/u7;->b:Lay0/a;

    .line 80
    .line 81
    if-eqz p0, :cond_0

    .line 82
    .line 83
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
