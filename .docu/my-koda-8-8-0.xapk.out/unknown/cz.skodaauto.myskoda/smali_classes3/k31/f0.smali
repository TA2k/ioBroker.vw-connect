.class public final Lk31/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr41/a;


# instance fields
.field public final a:Lf31/a;


# direct methods
.method public constructor <init>(Lf31/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk31/f0;->a:Lf31/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Lyy0/i;
    .locals 1

    .line 1
    iget-object p0, p0, Lk31/f0;->a:Lf31/a;

    .line 2
    .line 3
    iget-object p0, p0, Lf31/a;->a:Lb31/a;

    .line 4
    .line 5
    iget v0, p0, Lb31/a;->a:I

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lb31/a;->b:Lyy0/j1;

    .line 11
    .line 12
    check-cast p0, Lyy0/c2;

    .line 13
    .line 14
    new-instance v0, Lyy0/l1;

    .line 15
    .line 16
    invoke-direct {v0, p0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :pswitch_0
    iget-object p0, p0, Lb31/a;->b:Lyy0/j1;

    .line 21
    .line 22
    new-instance v0, Lyy0/l1;

    .line 23
    .line 24
    invoke-direct {v0, p0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :pswitch_1
    iget-object p0, p0, Lb31/a;->b:Lyy0/j1;

    .line 29
    .line 30
    new-instance v0, Lyy0/l1;

    .line 31
    .line 32
    invoke-direct {v0, p0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 33
    .line 34
    .line 35
    :goto_0
    return-object v0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lk31/f0;->a()Lyy0/i;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
