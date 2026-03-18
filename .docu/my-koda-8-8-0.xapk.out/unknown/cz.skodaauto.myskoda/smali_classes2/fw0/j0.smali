.class public final synthetic Lfw0/j0;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# static fields
.field public static final d:Lfw0/j0;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lfw0/j0;

    .line 2
    .line 3
    const-string v4, "<init>()V"

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    const-class v2, Lfw0/h0;

    .line 8
    .line 9
    const-string v3, "<init>"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lfw0/j0;->d:Lfw0/j0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance p0, Lfw0/h0;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lfw0/g0;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x2

    .line 10
    invoke-direct {v0, v2, v1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lfw0/h0;->d:Lfw0/g0;

    .line 14
    .line 15
    new-instance v0, Lew/g;

    .line 16
    .line 17
    const/16 v1, 0x18

    .line 18
    .line 19
    invoke-direct {v0, v1}, Lew/g;-><init>(I)V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lfw0/h0;->e:Lew/g;

    .line 23
    .line 24
    new-instance v0, Lel/a;

    .line 25
    .line 26
    const/16 v1, 0xb

    .line 27
    .line 28
    invoke-direct {v0, v1}, Lel/a;-><init>(I)V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lfw0/h0;->a:Lel/a;

    .line 32
    .line 33
    new-instance v0, Lel/a;

    .line 34
    .line 35
    const/16 v1, 0xa

    .line 36
    .line 37
    invoke-direct {v0, v1}, Lel/a;-><init>(I)V

    .line 38
    .line 39
    .line 40
    const/4 v1, 0x3

    .line 41
    iput v1, p0, Lfw0/h0;->f:I

    .line 42
    .line 43
    iput-object v0, p0, Lfw0/h0;->b:Lel/a;

    .line 44
    .line 45
    new-instance v0, Lew/g;

    .line 46
    .line 47
    invoke-direct {v0, p0}, Lew/g;-><init>(Lfw0/h0;)V

    .line 48
    .line 49
    .line 50
    new-instance v1, La71/a0;

    .line 51
    .line 52
    const/16 v2, 0x17

    .line 53
    .line 54
    invoke-direct {v1, v0, v2}, La71/a0;-><init>(Ljava/lang/Object;I)V

    .line 55
    .line 56
    .line 57
    iput-object v1, p0, Lfw0/h0;->c:La71/a0;

    .line 58
    .line 59
    return-object p0
.end method
