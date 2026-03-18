.class public final Lcc0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lcc0/a;

.field public final b:Lam0/c;


# direct methods
.method public constructor <init>(Lcc0/a;Lam0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcc0/g;->a:Lcc0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lcc0/g;->b:Lam0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/m1;
    .locals 3

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-asyncmessages-model-AsyncMessageTopic$-input$0"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, La7/k;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/16 v2, 0x10

    .line 10
    .line 11
    invoke-direct {v0, v2, p0, p1, v1}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    new-instance p0, Lyy0/m1;

    .line 15
    .line 16
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 17
    .line 18
    .line 19
    return-object p0
.end method

.method public final synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ldc0/b;

    .line 4
    .line 5
    iget-object v0, v0, Ldc0/b;->a:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lcc0/g;->a(Ljava/lang/String;)Lyy0/m1;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
