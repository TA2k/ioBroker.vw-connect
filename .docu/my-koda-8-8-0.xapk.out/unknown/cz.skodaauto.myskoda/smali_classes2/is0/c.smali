.class public final Lis0/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:I

.field public final synthetic e:Lis0/d;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Z


# direct methods
.method public constructor <init>(Lis0/d;Ljava/lang/String;Ljava/lang/String;ZLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lis0/c;->e:Lis0/d;

    .line 2
    .line 3
    iput-object p2, p0, Lis0/c;->f:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p3, p0, Lis0/c;->g:Ljava/lang/String;

    .line 6
    .line 7
    iput-boolean p4, p0, Lis0/c;->h:Z

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Lis0/c;

    .line 2
    .line 3
    iget-object v3, p0, Lis0/c;->g:Ljava/lang/String;

    .line 4
    .line 5
    iget-boolean v4, p0, Lis0/c;->h:Z

    .line 6
    .line 7
    iget-object v1, p0, Lis0/c;->e:Lis0/d;

    .line 8
    .line 9
    iget-object v2, p0, Lis0/c;->f:Ljava/lang/String;

    .line 10
    .line 11
    move-object v5, p1

    .line 12
    invoke-direct/range {v0 .. v5}, Lis0/c;-><init>(Lis0/d;Ljava/lang/String;Ljava/lang/String;ZLkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lis0/c;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lis0/c;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lis0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lis0/c;->d:I

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    if-eqz v2, :cond_1

    .line 9
    .line 10
    if-ne v2, v3, :cond_0

    .line 11
    .line 12
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 17
    .line 18
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 19
    .line 20
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw v0

    .line 24
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    iget-object v2, v0, Lis0/c;->e:Lis0/d;

    .line 28
    .line 29
    iget-object v2, v2, Lis0/d;->b:Lcz/myskoda/api/vas/SessionApi;

    .line 30
    .line 31
    sget-object v4, Lms0/h;->e:Lms0/g;

    .line 32
    .line 33
    iget-boolean v4, v0, Lis0/c;->h:Z

    .line 34
    .line 35
    if-eqz v4, :cond_2

    .line 36
    .line 37
    sget-object v4, Lcz/myskoda/api/vas/SessionRequestDto$AppMood;->dark:Lcz/myskoda/api/vas/SessionRequestDto$AppMood;

    .line 38
    .line 39
    :goto_0
    move-object/from16 v18, v4

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    sget-object v4, Lcz/myskoda/api/vas/SessionRequestDto$AppMood;->light:Lcz/myskoda/api/vas/SessionRequestDto$AppMood;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :goto_1
    new-instance v5, Lcz/myskoda/api/vas/SessionRequestDto;

    .line 46
    .line 47
    const/16 v19, 0x676

    .line 48
    .line 49
    const/16 v20, 0x0

    .line 50
    .line 51
    const-string v6, "myskoda://redirect/enrollment/vas/qr"

    .line 52
    .line 53
    const/4 v7, 0x0

    .line 54
    const/4 v8, 0x0

    .line 55
    iget-object v9, v0, Lis0/c;->g:Ljava/lang/String;

    .line 56
    .line 57
    const/4 v10, 0x0

    .line 58
    const/4 v11, 0x0

    .line 59
    const/4 v12, 0x0

    .line 60
    const-string v13, "VW_PE_VE_1"

    .line 61
    .line 62
    const-string v14, "myskoda://redirect/enrollment/vas/success"

    .line 63
    .line 64
    const/4 v15, 0x0

    .line 65
    const/16 v16, 0x0

    .line 66
    .line 67
    const-string v17, "myskoda://redirect/enrollment/vas/cancel"

    .line 68
    .line 69
    invoke-direct/range {v5 .. v20}, Lcz/myskoda/api/vas/SessionRequestDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/vas/SessionRequestDto$AppMood;ILkotlin/jvm/internal/g;)V

    .line 70
    .line 71
    .line 72
    iput v3, v0, Lis0/c;->d:I

    .line 73
    .line 74
    iget-object v3, v0, Lis0/c;->f:Ljava/lang/String;

    .line 75
    .line 76
    invoke-interface {v2, v3, v5, v0}, Lcz/myskoda/api/vas/SessionApi;->createSessionRequest(Ljava/lang/String;Lcz/myskoda/api/vas/SessionRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    if-ne v0, v1, :cond_3

    .line 81
    .line 82
    return-object v1

    .line 83
    :cond_3
    return-object v0
.end method
