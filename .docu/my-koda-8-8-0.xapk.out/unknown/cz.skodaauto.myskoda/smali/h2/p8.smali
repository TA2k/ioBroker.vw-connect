.class public final synthetic Lh2/p8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li2/n;

.field public final synthetic f:Lkotlin/jvm/internal/c0;


# direct methods
.method public synthetic constructor <init>(Li2/n;Lkotlin/jvm/internal/c0;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/p8;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/p8;->e:Li2/n;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/p8;->f:Lkotlin/jvm/internal/c0;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lh2/p8;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/Float;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    check-cast p2, Ljava/lang/Float;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 12
    .line 13
    .line 14
    move-result p2

    .line 15
    packed-switch v0, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lh2/p8;->e:Li2/n;

    .line 19
    .line 20
    iget-object v0, v0, Li2/n;->a:Li2/p;

    .line 21
    .line 22
    iget-object v1, v0, Li2/p;->j:Ll2/f1;

    .line 23
    .line 24
    invoke-virtual {v1, p1}, Ll2/f1;->p(F)V

    .line 25
    .line 26
    .line 27
    iget-object v0, v0, Li2/p;->k:Ll2/f1;

    .line 28
    .line 29
    invoke-virtual {v0, p2}, Ll2/f1;->p(F)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lh2/p8;->f:Lkotlin/jvm/internal/c0;

    .line 33
    .line 34
    iput p1, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 35
    .line 36
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    iget-object v0, p0, Lh2/p8;->e:Li2/n;

    .line 40
    .line 41
    iget-object v0, v0, Li2/n;->a:Li2/p;

    .line 42
    .line 43
    iget-object v1, v0, Li2/p;->j:Ll2/f1;

    .line 44
    .line 45
    invoke-virtual {v1, p1}, Ll2/f1;->p(F)V

    .line 46
    .line 47
    .line 48
    iget-object v0, v0, Li2/p;->k:Ll2/f1;

    .line 49
    .line 50
    invoke-virtual {v0, p2}, Ll2/f1;->p(F)V

    .line 51
    .line 52
    .line 53
    iget-object p0, p0, Lh2/p8;->f:Lkotlin/jvm/internal/c0;

    .line 54
    .line 55
    iput p1, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 56
    .line 57
    goto :goto_0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
