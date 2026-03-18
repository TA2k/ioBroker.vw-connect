.class public final synthetic La8/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:La8/f1;

.field public final synthetic f:Landroid/util/Pair;

.field public final synthetic g:Lh8/s;

.field public final synthetic h:Lh8/x;


# direct methods
.method public synthetic constructor <init>(La8/f1;Landroid/util/Pair;Lh8/s;Lh8/x;I)V
    .locals 0

    .line 1
    iput p5, p0, La8/c1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La8/c1;->e:La8/f1;

    .line 4
    .line 5
    iput-object p2, p0, La8/c1;->f:Landroid/util/Pair;

    .line 6
    .line 7
    iput-object p3, p0, La8/c1;->g:Lh8/s;

    .line 8
    .line 9
    iput-object p4, p0, La8/c1;->h:Lh8/x;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget v0, p0, La8/c1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La8/c1;->e:La8/f1;

    .line 7
    .line 8
    iget-object v0, v0, La8/f1;->e:Lac/i;

    .line 9
    .line 10
    iget-object v0, v0, Lac/i;->i:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lb8/e;

    .line 13
    .line 14
    iget-object v1, p0, La8/c1;->f:Landroid/util/Pair;

    .line 15
    .line 16
    iget-object v2, v1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v2, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    iget-object v1, v1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Lh8/b0;

    .line 27
    .line 28
    iget-object v3, p0, La8/c1;->g:Lh8/s;

    .line 29
    .line 30
    iget-object p0, p0, La8/c1;->h:Lh8/x;

    .line 31
    .line 32
    invoke-virtual {v0, v2, v1, v3, p0}, Lb8/e;->j(ILh8/b0;Lh8/s;Lh8/x;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :pswitch_0
    iget-object v0, p0, La8/c1;->e:La8/f1;

    .line 37
    .line 38
    iget-object v0, v0, La8/f1;->e:Lac/i;

    .line 39
    .line 40
    iget-object v0, v0, Lac/i;->i:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v0, Lb8/e;

    .line 43
    .line 44
    iget-object v1, p0, La8/c1;->f:Landroid/util/Pair;

    .line 45
    .line 46
    iget-object v2, v1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v2, Ljava/lang/Integer;

    .line 49
    .line 50
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    iget-object v1, v1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v1, Lh8/b0;

    .line 57
    .line 58
    iget-object v3, p0, La8/c1;->g:Lh8/s;

    .line 59
    .line 60
    iget-object p0, p0, La8/c1;->h:Lh8/x;

    .line 61
    .line 62
    invoke-virtual {v0, v2, v1, v3, p0}, Lb8/e;->F(ILh8/b0;Lh8/s;Lh8/x;)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
