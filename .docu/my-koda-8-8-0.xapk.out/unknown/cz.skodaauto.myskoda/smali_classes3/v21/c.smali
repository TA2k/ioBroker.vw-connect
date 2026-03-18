.class public final Lv21/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Lt21/a;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    iput p1, p0, Lv21/c;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance p1, Lmb/e;

    .line 10
    .line 11
    const/16 v0, 0xf

    .line 12
    .line 13
    invoke-direct {p1, v0}, Lmb/e;-><init>(I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lv21/c;->b:Lt21/a;

    .line 17
    .line 18
    new-instance p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 25
    .line 26
    .line 27
    new-instance p1, Lv21/f;

    .line 28
    .line 29
    invoke-direct {p1}, Lv21/f;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Lv21/c;->b:Lt21/a;

    .line 33
    .line 34
    new-instance p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 37
    .line 38
    .line 39
    new-instance p0, Ljava/lang/ThreadLocal;

    .line 40
    .line 41
    invoke-direct {p0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 42
    .line 43
    .line 44
    new-instance p0, Lv21/a;

    .line 45
    .line 46
    invoke-direct {p0}, Ljava/lang/InheritableThreadLocal;-><init>()V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
