.class public final Lkf0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lif0/u;


# direct methods
.method public constructor <init>(Lif0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/h;->a:Lif0/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lss0/j0;

    .line 2
    .line 3
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lkf0/h;->a:Lif0/u;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lif0/u;->a(Ljava/lang/String;)Llb0/y;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
