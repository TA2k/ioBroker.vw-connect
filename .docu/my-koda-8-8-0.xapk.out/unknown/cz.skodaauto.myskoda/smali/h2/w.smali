.class public final synthetic Lh2/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/r8;

.field public final synthetic f:Lc1/f1;

.field public final synthetic g:Lc1/f1;

.field public final synthetic h:Lc1/f1;


# direct methods
.method public synthetic constructor <init>(Lh2/r8;Lc1/f1;Lc1/f1;Lc1/f1;I)V
    .locals 0

    .line 1
    iput p5, p0, Lh2/w;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/w;->e:Lh2/r8;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/w;->f:Lc1/f1;

    .line 6
    .line 7
    iput-object p3, p0, Lh2/w;->g:Lc1/f1;

    .line 8
    .line 9
    iput-object p4, p0, Lh2/w;->h:Lc1/f1;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lh2/w;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/w;->e:Lh2/r8;

    .line 7
    .line 8
    iget-object v1, p0, Lh2/w;->f:Lc1/f1;

    .line 9
    .line 10
    iput-object v1, v0, Lh2/r8;->f:Lc1/a0;

    .line 11
    .line 12
    iget-object v1, p0, Lh2/w;->g:Lc1/f1;

    .line 13
    .line 14
    iput-object v1, v0, Lh2/r8;->g:Lc1/a0;

    .line 15
    .line 16
    iget-object p0, p0, Lh2/w;->h:Lc1/f1;

    .line 17
    .line 18
    iput-object p0, v0, Lh2/r8;->d:Lc1/j;

    .line 19
    .line 20
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object v0, p0, Lh2/w;->e:Lh2/r8;

    .line 24
    .line 25
    iget-object v1, p0, Lh2/w;->f:Lc1/f1;

    .line 26
    .line 27
    iput-object v1, v0, Lh2/r8;->f:Lc1/a0;

    .line 28
    .line 29
    iget-object v1, p0, Lh2/w;->g:Lc1/f1;

    .line 30
    .line 31
    iput-object v1, v0, Lh2/r8;->g:Lc1/a0;

    .line 32
    .line 33
    iget-object p0, p0, Lh2/w;->h:Lc1/f1;

    .line 34
    .line 35
    iput-object p0, v0, Lh2/r8;->d:Lc1/j;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
