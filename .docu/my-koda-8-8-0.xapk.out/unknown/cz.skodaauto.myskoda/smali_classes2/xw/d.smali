.class public final Lxw/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxw/p;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/reflect/AccessibleObject;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/reflect/AccessibleObject;I)V
    .locals 0

    .line 1
    iput p2, p0, Lxw/d;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lxw/d;->b:Ljava/lang/reflect/AccessibleObject;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final get(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p2, p0, Lxw/d;->a:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lxw/d;->b:Ljava/lang/reflect/AccessibleObject;

    .line 7
    .line 8
    check-cast p0, Ljava/lang/reflect/Field;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lxw/d;->b:Ljava/lang/reflect/AccessibleObject;

    .line 16
    .line 17
    check-cast p0, Ljava/lang/reflect/Method;

    .line 18
    .line 19
    const/4 p2, 0x0

    .line 20
    invoke-virtual {p0, p1, p2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_1
    iget-object p0, p0, Lxw/d;->b:Ljava/lang/reflect/AccessibleObject;

    .line 26
    .line 27
    check-cast p0, Ljava/lang/reflect/Method;

    .line 28
    .line 29
    const/4 p2, 0x0

    .line 30
    invoke-virtual {p0, p1, p2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
