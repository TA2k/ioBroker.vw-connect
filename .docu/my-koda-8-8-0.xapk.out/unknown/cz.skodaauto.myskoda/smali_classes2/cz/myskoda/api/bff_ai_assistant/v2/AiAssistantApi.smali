.class public interface abstract Lcz/myskoda/api/bff_ai_assistant/v2/AiAssistantApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000>\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008f\u0018\u00002\u00020\u0001J(\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00032\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u00062\u0008\u0008\u0001\u0010\u0007\u001a\u00020\u0008H\u00a7@\u00a2\u0006\u0002\u0010\tJ\u001e\u0010\n\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00032\u0008\u0008\u0001\u0010\u000c\u001a\u00020\rH\u00a7@\u00a2\u0006\u0002\u0010\u000eJ\u001e\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u00100\u00032\u0008\u0008\u0001\u0010\u0011\u001a\u00020\u0012H\u00a7@\u00a2\u0006\u0002\u0010\u0013\u00a8\u0006\u0014\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_ai_assistant/v2/AiAssistantApi;",
        "",
        "aiAssistantConversation",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff_ai_assistant/v2/ConversationResponseDto;",
        "conversationId",
        "",
        "conversationRequestDto",
        "Lcz/myskoda/api/bff_ai_assistant/v2/ConversationRequestDto;",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/ConversationRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "askAssistant",
        "Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantResponseDto;",
        "aiAssistantRequestDto",
        "Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;",
        "(Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "initiateAiAssistantConversation",
        "Lcz/myskoda/api/bff_ai_assistant/v2/InitiateConversationResponseDto;",
        "initiateConversationRequestDto",
        "Lcz/myskoda/api/bff_ai_assistant/v2/InitiateConversationRequestDto;",
        "(Lcz/myskoda/api/bff_ai_assistant/v2/InitiateConversationRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "bff-api_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public abstract aiAssistantConversation(Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/ConversationRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "conversationId"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_ai_assistant/v2/ConversationRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_ai_assistant/v2/ConversationRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_ai_assistant/v2/ConversationResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/ai-assistant/conversations/{conversationId}"
    .end annotation
.end method

.method public abstract askAssistant(Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/ai-assistant/ask"
    .end annotation
.end method

.method public abstract initiateAiAssistantConversation(Lcz/myskoda/api/bff_ai_assistant/v2/InitiateConversationRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_ai_assistant/v2/InitiateConversationRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_ai_assistant/v2/InitiateConversationRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_ai_assistant/v2/InitiateConversationResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/ai-assistant/conversations"
    .end annotation
.end method
