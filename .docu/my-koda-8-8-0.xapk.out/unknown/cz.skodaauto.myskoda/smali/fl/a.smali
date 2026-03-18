.class public final synthetic Lfl/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li01/f;


# direct methods
.method public synthetic constructor <init>(Li01/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Lfl/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfl/a;->e:Li01/f;

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
    iget v0, p0, Lfl/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lgi/c;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$log"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lfl/a;->e:Li01/f;

    .line 14
    .line 15
    iget-object p0, p0, Li01/f;->e:Ld01/k0;

    .line 16
    .line 17
    iget-object p1, p0, Ld01/k0;->b:Ljava/lang/String;

    .line 18
    .line 19
    iget-object p0, p0, Ld01/k0;->a:Ld01/a0;

    .line 20
    .line 21
    invoke-virtual {p0}, Ld01/a0;->b()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string v0, " "

    .line 26
    .line 27
    const-string v1, " returned 401. Retrying with new token"

    .line 28
    .line 29
    invoke-static {p1, v0, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_0
    const-string v0, "$this$log"

    .line 35
    .line 36
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Lfl/a;->e:Li01/f;

    .line 40
    .line 41
    iget-object p0, p0, Li01/f;->e:Ld01/k0;

    .line 42
    .line 43
    iget-object p1, p0, Ld01/k0;->b:Ljava/lang/String;

    .line 44
    .line 45
    iget-object p0, p0, Ld01/k0;->a:Ld01/a0;

    .line 46
    .line 47
    invoke-virtual {p0}, Ld01/a0;->b()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string v0, "Inserting token from host app into "

    .line 52
    .line 53
    const-string v1, " "

    .line 54
    .line 55
    invoke-static {v0, p1, v1, p0}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
