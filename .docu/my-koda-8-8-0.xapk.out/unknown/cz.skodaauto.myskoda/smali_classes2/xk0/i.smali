.class public final Lxk0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Lxk0/i;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lxk0/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lxk0/i;->d:Lxk0/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lto0/h;

    .line 2
    .line 3
    iget-object p0, p1, Lto0/h;->a:Ljava/lang/String;

    .line 4
    .line 5
    const-string p1, "$v$c$cz-skodaauto-myskoda-library-powerpass-model-EvseId$-it$0"

    .line 6
    .line 7
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    return-object p0
.end method
