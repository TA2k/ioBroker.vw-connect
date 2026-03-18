.class public final Lmg0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lmg0/e;

.field public final synthetic f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;


# direct methods
.method public synthetic constructor <init>(Lmg0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;I)V
    .locals 0

    .line 1
    iput p3, p0, Lmg0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmg0/c;->e:Lmg0/e;

    .line 4
    .line 5
    iput-object p2, p0, Lmg0/c;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p2, p0, Lmg0/c;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llg0/a;

    .line 7
    .line 8
    iget-wide p1, p1, Llg0/a;->a:J

    .line 9
    .line 10
    iget-object v0, p0, Lmg0/c;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    iget-object p0, p0, Lmg0/c;->e:Lmg0/e;

    .line 14
    .line 15
    invoke-static {p0, v0, p1, p2, v1}, Lmg0/e;->a(Lmg0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;JZ)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    iget-object p0, p0, Lmg0/e;->b:Lig0/g;

    .line 20
    .line 21
    new-instance v1, Llg0/i;

    .line 22
    .line 23
    invoke-direct {v1, p1, p2, v0}, Llg0/i;-><init>(JZ)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lig0/g;->i:Lyy0/q1;

    .line 27
    .line 28
    invoke-virtual {p0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    check-cast p1, Llg0/a;

    .line 35
    .line 36
    iget-wide p1, p1, Llg0/a;->a:J

    .line 37
    .line 38
    iget-object v0, p0, Lmg0/c;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    iget-object p0, p0, Lmg0/c;->e:Lmg0/e;

    .line 42
    .line 43
    invoke-static {p0, v0, p1, p2, v1}, Lmg0/e;->a(Lmg0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;JZ)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    iget-object p0, p0, Lmg0/e;->b:Lig0/g;

    .line 48
    .line 49
    new-instance v1, Llg0/h;

    .line 50
    .line 51
    invoke-direct {v1, p1, p2, v0}, Llg0/h;-><init>(JZ)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p0, Lig0/g;->f:Lyy0/q1;

    .line 55
    .line 56
    invoke-virtual {p0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
