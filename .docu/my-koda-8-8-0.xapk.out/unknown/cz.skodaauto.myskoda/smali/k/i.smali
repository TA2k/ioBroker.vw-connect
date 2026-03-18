.class public final Lk/i;
.super Ljp/of;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:Z

.field public c:I

.field public final synthetic d:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lk/j;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lk/i;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lk/i;->d:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 3
    iput-boolean p1, p0, Lk/i;->b:Z

    .line 4
    iput p1, p0, Lk/i;->c:I

    return-void
.end method

.method public constructor <init>(Lm/w2;I)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lk/i;->a:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p1, p0, Lk/i;->d:Ljava/lang/Object;

    iput p2, p0, Lk/i;->c:I

    const/4 p1, 0x0

    .line 7
    iput-boolean p1, p0, Lk/i;->b:Z

    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 1
    iget v0, p0, Lk/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    const/4 v0, 0x1

    .line 8
    iput-boolean v0, p0, Lk/i;->b:Z

    .line 9
    .line 10
    return-void

    .line 11
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final b()V
    .locals 1

    .line 1
    iget v0, p0, Lk/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lk/i;->d:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lm/w2;

    .line 9
    .line 10
    iget-object p0, p0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p0, v0}, Landroid/view/View;->setVisibility(I)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    iget-boolean v0, p0, Lk/i;->b:Z

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x1

    .line 23
    iput-boolean v0, p0, Lk/i;->b:Z

    .line 24
    .line 25
    iget-object p0, p0, Lk/i;->d:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lk/j;

    .line 28
    .line 29
    iget-object p0, p0, Lk/j;->d:Ld6/x0;

    .line 30
    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    invoke-interface {p0}, Ld6/x0;->b()V

    .line 34
    .line 35
    .line 36
    :cond_1
    :goto_0
    return-void

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c()V
    .locals 3

    .line 1
    iget v0, p0, Lk/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lk/i;->b:Z

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lk/i;->d:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lm/w2;

    .line 13
    .line 14
    iget-object v0, v0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 15
    .line 16
    iget p0, p0, Lk/i;->c:I

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Landroid/view/View;->setVisibility(I)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void

    .line 22
    :pswitch_0
    iget v0, p0, Lk/i;->c:I

    .line 23
    .line 24
    add-int/lit8 v0, v0, 0x1

    .line 25
    .line 26
    iput v0, p0, Lk/i;->c:I

    .line 27
    .line 28
    iget-object v1, p0, Lk/i;->d:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v1, Lk/j;

    .line 31
    .line 32
    iget-object v2, v1, Lk/j;->a:Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-ne v0, v2, :cond_2

    .line 39
    .line 40
    iget-object v0, v1, Lk/j;->d:Ld6/x0;

    .line 41
    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    invoke-interface {v0}, Ld6/x0;->c()V

    .line 45
    .line 46
    .line 47
    :cond_1
    const/4 v0, 0x0

    .line 48
    iput v0, p0, Lk/i;->c:I

    .line 49
    .line 50
    iput-boolean v0, p0, Lk/i;->b:Z

    .line 51
    .line 52
    iput-boolean v0, v1, Lk/j;->e:Z

    .line 53
    .line 54
    :cond_2
    return-void

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
