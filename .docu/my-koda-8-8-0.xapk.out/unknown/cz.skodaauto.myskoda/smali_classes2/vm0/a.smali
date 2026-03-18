.class public final Lvm0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ltm0/c;

.field public final b:Lvm0/b;


# direct methods
.method public constructor <init>(Ltm0/c;Lvm0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvm0/a;->a:Ltm0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lvm0/a;->b:Lvm0/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 5

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-input$0"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvm0/a;->a:Ltm0/c;

    .line 7
    .line 8
    iget-object v1, v0, Ltm0/c;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v2, Llo0/b;

    .line 11
    .line 12
    const/16 v3, 0x16

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    invoke-direct {v2, v3, v0, p1, v4}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    sget-object p1, Ltm0/b;->d:Ltm0/b;

    .line 19
    .line 20
    invoke-virtual {v1, v2, p1, v4}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    new-instance v0, Ls10/a0;

    .line 25
    .line 26
    const/16 v1, 0x13

    .line 27
    .line 28
    invoke-direct {v0, p0, v4, v1}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    new-instance p0, Lne0/n;

    .line 32
    .line 33
    const/4 v1, 0x5

    .line 34
    invoke-direct {p0, p1, v0, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 35
    .line 36
    .line 37
    return-object p0
.end method

.method public final synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lss0/j0;

    .line 4
    .line 5
    iget-object v0, v0, Lss0/j0;->d:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lvm0/a;->a(Ljava/lang/String;)Lyy0/i;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
