.class public final synthetic Lh8/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/f;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ld8/f;

.field public final synthetic f:Lh8/s;

.field public final synthetic g:Lh8/x;


# direct methods
.method public synthetic constructor <init>(Ld8/f;Lh8/s;Lh8/x;I)V
    .locals 0

    .line 1
    iput p4, p0, Lh8/e0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh8/e0;->e:Ld8/f;

    .line 4
    .line 5
    iput-object p2, p0, Lh8/e0;->f:Lh8/s;

    .line 6
    .line 7
    iput-object p3, p0, Lh8/e0;->g:Lh8/x;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 3

    .line 1
    iget v0, p0, Lh8/e0;->d:I

    .line 2
    .line 3
    check-cast p1, Lh8/h0;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lh8/e0;->e:Ld8/f;

    .line 9
    .line 10
    iget v1, v0, Ld8/f;->a:I

    .line 11
    .line 12
    iget-object v0, v0, Ld8/f;->b:Lh8/b0;

    .line 13
    .line 14
    iget-object v2, p0, Lh8/e0;->f:Lh8/s;

    .line 15
    .line 16
    iget-object p0, p0, Lh8/e0;->g:Lh8/x;

    .line 17
    .line 18
    invoke-interface {p1, v1, v0, v2, p0}, Lh8/h0;->F(ILh8/b0;Lh8/s;Lh8/x;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_0
    iget-object v0, p0, Lh8/e0;->e:Ld8/f;

    .line 23
    .line 24
    iget v1, v0, Ld8/f;->a:I

    .line 25
    .line 26
    iget-object v0, v0, Ld8/f;->b:Lh8/b0;

    .line 27
    .line 28
    iget-object v2, p0, Lh8/e0;->f:Lh8/s;

    .line 29
    .line 30
    iget-object p0, p0, Lh8/e0;->g:Lh8/x;

    .line 31
    .line 32
    invoke-interface {p1, v1, v0, v2, p0}, Lh8/h0;->j(ILh8/b0;Lh8/s;Lh8/x;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
